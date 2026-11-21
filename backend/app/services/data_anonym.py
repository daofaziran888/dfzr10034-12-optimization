"""脱敏引擎领域服务：字段级脱敏算法的配置、可逆性控制、密钥版本管理和整批失败恢复。

接收分级标签，对敏感字段应用脱敏规则。

整批脱敏的失败恢复设计：
- 批次管线（open_batch / run_batch / resume_batch）：行×字段任务计划落存，
  中断或部分失败后可按批次号续做，已成功的字段任务绝不二次掩码；
- 行级回执：每个字段任务沿现有 data_anonym → operation_log 调用链记录
  行号、批次号、规则编号、规则版本与结果摘要，日志绝不写入敏感原值；
- 规则版本：恢复处理按既有规则编号解析规则，规则内容更正后版本自动递增，
  未处理行采用新版本，已处理行保留旧版本回执，审查员可按同一规则版本逐行核对；
- 失败批次：失败任务保留在批次内可核对，修正规则后 resume 自动重试；
- 审计汇总：delivery_audit 输出"行号 → 字段 → 规则版本"的交割范围，
  审计员只凭行号和版本即可查明实际交割范围。
"""
from __future__ import annotations

import hashlib
import re
import time as _time
from typing import Any

from app.services.base import BaseModuleService
from app.store import store


class DataAnonymService(BaseModuleService):
    MODULE = "data_anonym"
    ENTITY = "脱敏规则"
    OPERATION_TERM = "校验"
    LIST_FIELDS = ["规则编号", "目标字段", "脱敏算法", "保留位数", "替换字符", "适用场景", "可逆标志", "密钥版本"]
    REQUIRED_FIELDS = ["规则编号", "目标字段", "脱敏算法"]
    STATUS_ORDER = ["草稿", "已审查", "已生效", "已停用"]
    ACTION_RULES = {"提交审查": "已审查", "启效规则": "已生效", "停用规则": "已停用"}
    NEGATIVE_ACTIONS = ["停用规则"]

    # 算法别名：中文配置名归一到内部标识；无法识别的算法视为失败，
    # 不再静默放行原值，避免未经处理的敏感值流入成品。
    ALGORITHM_ALIASES = {
        "mask": "mask", "掩码": "mask",
        "hash": "hash", "哈希": "hash",
        "truncate": "truncate", "截断": "truncate",
        "replace": "replace", "替换": "replace",
        "reversible": "reversible", "可逆": "reversible",
    }

    # 批次检查点存放于管线状态：批次索引 + 每批次一份检查点
    BATCH_INDEX_KEY = "anonym_batches"
    BATCH_KEY_PREFIX = "anonym_batch:"

    # ── 单值脱敏（现有调用链，增加行级回执上下文） ─────────────

    def apply_anonymization(
        self,
        rule_id: int,
        value: str,
        *,
        row_no: int | None = None,
        batch_id: str | None = None,
    ) -> dict[str, Any]:
        """应用脱敏规则处理数据值。

        row_no / batch_id 为可选的行级回执上下文：传入后，操作日志会带上
        行号、批次号和规则版本，供断点续做与审计核对定位。
        """
        rule = self.get_entry(rule_id)
        if not rule:
            self._log_anonymization(
                None, value, value, row_no=row_no, batch_id=batch_id,
                outcome="失败", reason=f"脱敏规则{rule_id}不存在",
            )
            return {"ok": False, "error": "脱敏规则不存在", "result": value}

        raw_algorithm = str(rule.get("脱敏算法", "mask")).strip()
        algorithm = self.ALGORITHM_ALIASES.get(raw_algorithm.casefold())
        if algorithm is None:
            # 未知算法：按失败处理并留回执，绝不放行未处理原值
            self._log_anonymization(
                rule, value, value, row_no=row_no, batch_id=batch_id,
                outcome="失败", reason=f"未知脱敏算法:{raw_algorithm}",
            )
            return {"ok": False, "error": f"未知脱敏算法：{raw_algorithm}", "result": value}

        preserve = int(rule.get("保留位数", "0") or 0)
        replace_char = rule.get("替换字符", "*")
        original = value

        if algorithm == "mask":
            # 掩码脱敏：保留前preserve位，其余替换
            if len(value) <= preserve:
                result = value
            else:
                result = value[:preserve] + replace_char * (len(value) - preserve)
        elif algorithm == "hash":
            # 哈希脱敏：SHA-256后取前16位
            result = hashlib.sha256(value.encode()).hexdigest()[:16]
        elif algorithm == "truncate":
            # 截断脱敏
            result = value[:preserve] if preserve > 0 else ""
        elif algorithm == "replace":
            # 替换脱敏
            result = replace_char * len(value)
        elif algorithm == "reversible":
            # 可逆脱敏（带密钥）
            key_version = rule.get("密钥版本", "v1")
            key_material = f"{rule.get('规则编号','')}:{key_version}"
            result = self._reversible_encode(value, key_material)
        else:  # pragma: no cover - 别名表已兜底
            self._log_anonymization(
                rule, value, value, row_no=row_no, batch_id=batch_id,
                outcome="失败", reason=f"未知脱敏算法:{raw_algorithm}",
            )
            return {"ok": False, "error": f"未知脱敏算法：{raw_algorithm}", "result": value}

        # 记录审计日志（行级回执，不含敏感原值）
        self._log_anonymization(rule, original, result, row_no=row_no, batch_id=batch_id)

        return {
            "ok": True,
            "rule_id": rule_id,
            "algorithm": algorithm,
            "rule_version": self._rule_version(rule),
            "original_length": len(original),
            "result": result,
        }

    def _reversible_encode(self, value: str, key: str) -> str:
        """可逆编码（带密钥）。"""
        key_hash = hashlib.sha256(key.encode()).digest()
        result = []
        for i, ch in enumerate(value):
            kb = key_hash[i % len(key_hash)]
            result.append(chr(ord(ch) ^ kb % 256))
        return ''.join(result)

    def _rule_version(self, rule: dict[str, Any]) -> str:
        """读取规则版本；既有规则没有版本字段时按 v1 处理，兼容已有规则编号。"""
        return str(rule.get("规则版本") or "v1")

    def _result_digest(self, batch_id: str | None, rule: dict[str, Any], result: str) -> str:
        """脱敏结果的核对摘要：带批次盐的哈希，可核对交付值，反推不出敏感原值。"""
        salt = f"{batch_id or 'single'}:{rule.get('规则编号', '')}"
        return hashlib.sha256(f"{salt}:{result}".encode()).hexdigest()[:12]

    def _log_anonymization(
        self,
        rule: dict[str, Any] | None,
        original: str,
        result: str,
        *,
        row_no: int | None = None,
        batch_id: str | None = None,
        outcome: str | None = None,
        reason: str = "",
    ) -> None:
        """将脱敏操作记录到操作日志表（Pipeline 8）。

        行级回执：行号、批次号、规则编号、规则版本与结果摘要随日志落存；
        original 仅用于判断处理结果，绝不写入日志，日志不留敏感原值。
        """
        rule = rule or {}
        now = _time.strftime("%Y-%m-%d %H:%M:%S")
        if outcome is None:
            outcome = "成功" if result != original else "跳过"
        log_id = store.next_id("operation_log")
        log_entry = {
            "id": log_id,
            "记录编号": f"OPER-ANON-{log_id:04d}",
            "目标资产": rule.get("目标字段", ""),
            "操作人": "脱敏引擎",
            "操作类型": f"脱敏-{rule.get('脱敏算法', '')}",
            "操作时间": now,
            "来源节点": "localhost",
            "处理结果": outcome,
            "异常结论": reason or "自动",
            "规则编号": rule.get("规则编号", ""),
            "规则版本": self._rule_version(rule) if rule else "",
            "status": "已记录",
            "pending": False,
            "abnormal": outcome == "失败",
            "created_at": now,
        }
        if row_no is not None:
            log_entry["行号"] = row_no
        if batch_id is not None:
            log_entry["批次号"] = batch_id
        if outcome != "失败":
            log_entry["结果摘要"] = self._result_digest(batch_id, rule, result)
            log_entry["结果长度"] = len(result)
        store.rows("operation_log").append(log_entry)

    # ── 规则版本管理 ──────────────────────────────────────────

    def _bump_version(self, current: str) -> str:
        """版本号递增：vN → v(N+1)；自定义后缀 -rN 同样递增；其余追加 -r2。"""
        cur = (current or "v1").strip() or "v1"
        match = re.fullmatch(r"v(\d+)", cur)
        if match:
            return f"v{int(match.group(1)) + 1}"
        match = re.fullmatch(r"(.+)-r(\d+)", cur)
        if match:
            return f"{match.group(1)}-r{int(match.group(2)) + 1}"
        return f"{cur}-r2"

    def update_masking_rule(self, rule_id: int, updates: dict[str, Any]) -> tuple[dict[str, Any] | None, str]:
        """更正脱敏规则内容并递增规则版本。

        规则编号保持不变，恢复处理按既有编号即可解析到更正后的规则；
        updates 里显式给出"规则版本"时采用指定版本，否则自动递增。
        """
        rule = self.get_entry(rule_id)
        if rule is None:
            return None, f"{self.ENTITY} {rule_id} 不存在或已归档"
        old_version = self._rule_version(rule)
        for key, val in updates.items():
            if key == "规则版本":
                continue
            rule[key] = val
        new_version = str(updates.get("规则版本") or "").strip() or self._bump_version(old_version)
        rule["规则版本"] = new_version
        rule["updated_at"] = _time.strftime("%Y-%m-%d %H:%M:%S")
        store.log_change(
            self.MODULE, rule_id, "更新规则",
            before=old_version, after=new_version,
            source="masking_rule_update", scope=self.MODULE,
        )
        return rule, f"{self.ENTITY}已更新至{new_version}"

    # ── 整批脱敏批次管线：断点续做与失败恢复 ───────────────────

    def _load_batch(self, batch_id: str) -> dict[str, Any] | None:
        return store.get_pipeline_state(f"{self.BATCH_KEY_PREFIX}{batch_id}")

    def _save_batch(self, batch: dict[str, Any]) -> None:
        store.set_pipeline_state(f"{self.BATCH_KEY_PREFIX}{batch['batch_id']}", batch)

    def _active_rule_for(self, field_path: str) -> dict[str, Any] | None:
        """按目标字段解析当前已生效的脱敏规则（每次执行时重新解析）。

        规则编号不变、内容更正后，续做任务自动采用更正后的规则与版本。
        """
        matching = [
            r for r in store.rows(self.MODULE)
            if r.get("status") == "已生效" and r.get("目标字段", "") == field_path
        ]
        return matching[0] if matching else None

    def open_batch(self, asset_code: str, records: list[dict[str, Any]]) -> dict[str, Any]:
        """开立整批脱敏批次：登记行×敏感字段任务计划，返回批次号。

        任务计划只记录行号与字段路径，具体规则在执行时按编号解析，
        因此中断期间更正规则后，续做任务自动采用新版本。
        """
        classifications = [
            c for c in store.rows("classification")
            if c.get("status") == "已确认" and str(c.get("目标字段", "")).startswith(f"{asset_code}.")
        ]
        plan: list[dict[str, Any]] = []
        for row_no in range(1, len(records) + 1):
            for cls in classifications:
                field_path = str(cls.get("目标字段", ""))
                parts = field_path.split(".")
                if len(parts) < 2:
                    continue
                plan.append({"row_no": row_no, "field": parts[-1], "field_path": field_path})

        index = store.get_pipeline_state(self.BATCH_INDEX_KEY) or {"batches": []}
        batch_id = f"ANB-{len(index['batches']) + 1:04d}"
        now = _time.strftime("%Y-%m-%d %H:%M:%S")
        batch = {
            "batch_id": batch_id,
            "asset_code": asset_code,
            "status": "进行中",
            "total_rows": len(records),
            "rows": [dict(r) for r in records],
            "plan": plan,
            "receipts": [],
            "delivered_rows": [],
            "row_versions": {},
            "failed": [],
            "created_at": now,
            "updated_at": now,
        }
        self._save_batch(batch)
        index["batches"].append(batch_id)
        store.set_pipeline_state(self.BATCH_INDEX_KEY, index)
        return {
            "ok": True,
            "batch_id": batch_id,
            "asset_code": asset_code,
            "total_rows": len(records),
            "planned_tasks": len(plan),
        }

    def run_batch(self, batch_id: str, *, interrupt_after: int | None = None) -> dict[str, Any]:
        """执行（或续做）批次任务。

        - 已有成功回执的字段任务直接跳过，断线重试不会二次掩码；
        - 失败任务保留失败回执，修正规则后再次执行自动重试；
        - interrupt_after 用于演练停机：处理完指定数量的字段任务后中断，
          批次状态置为"已中断"，检查点已落存，可随时 resume_batch 续做。
        """
        batch = self._load_batch(batch_id)
        if batch is None:
            return {"ok": False, "error": f"脱敏批次 {batch_id} 不存在"}
        if batch["status"] == "已完成":
            return self._report(batch)

        batch["status"] = "进行中"
        done = 0
        interrupted = False
        for task in batch["plan"]:
            row_no, field = task["row_no"], task["field"]
            if self._task_succeeded(batch, row_no, field):
                continue  # 已成功：跳过，绝不二次掩码

            rule = self._active_rule_for(task["field_path"])
            if rule is None:
                self._record_failure(batch, task, None, "无已生效的脱敏规则")
            else:
                original = str(batch["rows"][row_no - 1].get(field, ""))
                result = self.apply_anonymization(
                    rule["id"], original, row_no=row_no, batch_id=batch_id,
                )
                if result["ok"]:
                    batch["rows"][row_no - 1][field] = result["result"]
                    self._record_success(batch, task, rule, result["result"])
                else:
                    self._record_failure(batch, task, rule, result.get("error", "脱敏失败"))

            done += 1
            if interrupt_after is not None and done >= interrupt_after:
                interrupted = True
                break

        self._refresh_batch_outcome(batch)
        if interrupted:
            batch["status"] = "已中断"
            self.emit_event("anonymization_interrupted", {
                "asset_code": batch["asset_code"],
                "batch_id": batch_id,
                "delivered_rows": list(batch["delivered_rows"]),
                "remaining_tasks": sum(
                    1 for t in batch["plan"]
                    if not self._task_succeeded(batch, t["row_no"], t["field"])
                ),
            })
        elif not batch["failed"]:
            batch["status"] = "已完成"
            self.emit_event("anonymization_completed", {
                "asset_code": batch["asset_code"],
                "batch_id": batch_id,
                "records_count": batch["total_rows"],
                "fields_anonymized": sum(
                    1 for r in batch["receipts"] if r["status"] == "成功"
                ),
                "delivered_rows": list(batch["delivered_rows"]),
            })
        else:
            batch["status"] = "部分失败"
        batch["updated_at"] = _time.strftime("%Y-%m-%d %H:%M:%S")
        self._save_batch(batch)
        return self._report(batch)

    def resume_batch(self, batch_id: str) -> dict[str, Any]:
        """断点续做：跳过已成功任务，按当前规则（可能已更正版本）处理剩余任务。"""
        return self.run_batch(batch_id)

    def find_recoverable_batches(self) -> list[dict[str, Any]]:
        """列出可恢复批次（已中断或部分失败），保留可核对的失败批次。"""
        index = store.get_pipeline_state(self.BATCH_INDEX_KEY) or {"batches": []}
        recoverable = []
        for batch_id in index["batches"]:
            batch = self._load_batch(batch_id)
            if batch and batch["status"] in ("已中断", "部分失败"):
                recoverable.append({
                    "batch_id": batch_id,
                    "asset_code": batch["asset_code"],
                    "status": batch["status"],
                    "total_rows": batch["total_rows"],
                    "delivered_rows": list(batch["delivered_rows"]),
                    "failed_tasks": len(batch["failed"]),
                    "updated_at": batch["updated_at"],
                })
        return recoverable

    def batch_report(self, batch_id: str) -> dict[str, Any]:
        """按批次号查询批次报告（含当前行数据与回执）。"""
        batch = self._load_batch(batch_id)
        if batch is None:
            return {"ok": False, "error": f"脱敏批次 {batch_id} 不存在"}
        return self._report(batch)

    def delivery_audit(self, batch_id: str) -> dict[str, Any]:
        """审计汇总：只凭行号和规则版本即可查明实际交割范围。

        随已交付范围实时更新：一行所有敏感字段都脱敏成功后才计入已交付，
        每个字段记录实际使用的规则版本，失败批次单独列出供核对。
        """
        batch = self._load_batch(batch_id)
        if batch is None:
            return {"ok": False, "error": f"脱敏批次 {batch_id} 不存在"}
        version_scope: dict[str, list[int]] = {}
        for row_no_str, fields in batch["row_versions"].items():
            for version in set(fields.values()):
                version_scope.setdefault(version, []).append(int(row_no_str))
        for rows in version_scope.values():
            rows.sort()
        delivered = list(batch["delivered_rows"])
        return {
            "ok": True,
            "batch_id": batch_id,
            "asset_code": batch["asset_code"],
            "status": batch["status"],
            "total_rows": batch["total_rows"],
            "delivered_rows": delivered,
            "pending_rows": [n for n in range(1, batch["total_rows"] + 1) if n not in delivered],
            "row_versions": {k: dict(v) for k, v in batch["row_versions"].items()},
            "version_scope": version_scope,
            "failed": [dict(f) for f in batch["failed"]],
            "receipt_count": len(batch["receipts"]),
            "updated_at": batch["updated_at"],
        }

    # ── 批次内部工具 ──────────────────────────────────────────

    def _task_succeeded(self, batch: dict[str, Any], row_no: int, field: str) -> bool:
        """该行该字段是否已有成功回执（续做时据此跳过，避免二次掩码）。"""
        return any(
            r["row_no"] == row_no and r["field"] == field and r["status"] == "成功"
            for r in batch["receipts"]
        )

    def _record_success(self, batch: dict[str, Any], task: dict[str, Any], rule: dict[str, Any], result: str) -> None:
        batch["receipts"].append({
            "row_no": task["row_no"],
            "field": task["field"],
            "field_path": task["field_path"],
            "规则编号": rule.get("规则编号", ""),
            "规则版本": self._rule_version(rule),
            "status": "成功",
            "结果摘要": self._result_digest(batch["batch_id"], rule, result),
            "结果长度": len(result),
            "time": _time.strftime("%Y-%m-%d %H:%M:%S"),
        })

    def _record_failure(
        self,
        batch: dict[str, Any],
        task: dict[str, Any],
        rule: dict[str, Any] | None,
        reason: str,
    ) -> None:
        """记录失败回执：留在失败批次内可核对，日志不写敏感原值。"""
        rule = rule or {}
        batch["receipts"].append({
            "row_no": task["row_no"],
            "field": task["field"],
            "field_path": task["field_path"],
            "规则编号": rule.get("规则编号", ""),
            "规则版本": self._rule_version(rule) if rule else "",
            "status": "失败",
            "reason": reason,
            "time": _time.strftime("%Y-%m-%d %H:%M:%S"),
        })
        self._log_anonymization(
            rule or None, "", "", row_no=task["row_no"], batch_id=batch["batch_id"],
            outcome="失败", reason=reason,
        )
        # 失败回执同时落入操作日志时补齐目标字段，便于沿调用链定位
        store.rows("operation_log")[-1]["目标资产"] = task["field_path"]

    def _refresh_batch_outcome(self, batch: dict[str, Any]) -> None:
        """按最新回执重算已交付范围、行版本与失败批次（审计汇总随之更新）。"""
        latest: dict[tuple[int, str], dict[str, Any]] = {}
        for receipt in batch["receipts"]:
            latest[(receipt["row_no"], receipt["field"])] = receipt

        plan_fields: dict[int, list[str]] = {}
        for task in batch["plan"]:
            plan_fields.setdefault(task["row_no"], [])
            if task["field"] not in plan_fields[task["row_no"]]:
                plan_fields[task["row_no"]].append(task["field"])

        delivered: list[int] = []
        row_versions: dict[str, dict[str, str]] = {}
        if not batch["plan"]:
            # 无敏感字段任务：全部行直接可交付
            delivered = list(range(1, batch["total_rows"] + 1))
            row_versions = {str(n): {} for n in delivered}
        else:
            for row_no in sorted(plan_fields):
                receipts = {f: latest.get((row_no, f)) for f in plan_fields[row_no]}
                if all(rc and rc["status"] == "成功" for rc in receipts.values()):
                    delivered.append(row_no)
                    row_versions[str(row_no)] = {
                        f: receipts[f]["规则版本"] for f in sorted(receipts)
                    }

        failed: list[dict[str, Any]] = []
        for task in batch["plan"]:
            receipt = latest.get((task["row_no"], task["field"]))
            if receipt is None or receipt["status"] != "成功":
                failed.append({
                    "row_no": task["row_no"],
                    "field": task["field"],
                    "field_path": task["field_path"],
                    "规则编号": receipt.get("规则编号", "") if receipt else "",
                    "规则版本": receipt.get("规则版本", "") if receipt else "",
                    "reason": receipt.get("reason", "未处理") if receipt else "未处理",
                })

        batch["delivered_rows"] = delivered
        batch["row_versions"] = row_versions
        batch["failed"] = failed

    def _report(self, batch: dict[str, Any]) -> dict[str, Any]:
        """批次报告：当前行数据、交付范围、失败批次与审计汇总。"""
        anonymized_fields: dict[str, list[str]] = {}
        for receipt in batch["receipts"]:
            if receipt["status"] == "成功":
                anonymized_fields.setdefault(receipt["规则编号"], []).append(receipt["field"])
        delivered = list(batch["delivered_rows"])
        return {
            "ok": True,
            "batch_id": batch["batch_id"],
            "asset_code": batch["asset_code"],
            "status": batch["status"],
            "records": [dict(r) for r in batch["rows"]],
            "total_rows": batch["total_rows"],
            "delivered_rows": delivered,
            "pending_rows": [n for n in range(1, batch["total_rows"] + 1) if n not in delivered],
            "failed": [dict(f) for f in batch["failed"]],
            "receipts": [dict(r) for r in batch["receipts"]],
            "anonymized_fields": anonymized_fields,
            "audit": self.delivery_audit(batch["batch_id"]),
        }

    # ── 兼容旧接口：整批脱敏 ───────────────────────────────────

    def anonymize_dataset(self, asset_code: str, records: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, list[str]]]:
        """对整个数据集应用脱敏规则，基于分级标签。

        内部走批次管线：行级回执、断点续做与审计汇总自动生效；
        返回结构保持 (脱敏后记录, {规则编号: [字段...]}) 不变。
        """
        opened = self.open_batch(asset_code, records)
        report = self.run_batch(opened["batch_id"])
        return report["records"], report["anonymized_fields"]
