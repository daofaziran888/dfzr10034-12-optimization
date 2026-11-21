"""整批脱敏失败恢复测试：断点续做、规则版本核对、失败批次保留与日志合规。

场景主线（对应交付演练）：
- 交付样本为 区域码 / 联系方式 / 对账金额 各一列，后两列为敏感列；
- 第二行联系字段处理完、第三行还未开始时停机（interrupt_after=3）；
- 值班员把联系方式规则更正为有效遮盖规则（版本 v1 → v2）再续做；
- 成品不得出现未经处理的联系方式，已脱敏字段不得二次掩码；
- 审计员只凭行号和规则版本即可查明实际交割范围；
- 操作日志记录行号与规则版本，且不写入敏感原值。
"""
import json

import app.store as store_mod
from app.services.classification import ClassificationService
from app.services.data_anonym import DataAnonymService

ASSET = "DELIV-001"

# 交付样本：区域码、联系方式、对账金额各一列（两个敏感列）
SAMPLE_ROWS = [
    {"区域码": "010", "联系方式": "13800138000", "对账金额": "1024.50"},
    {"区域码": "021", "联系方式": "13900139000", "对账金额": "2048.75"},
    {"区域码": "0755", "联系方式": "13700137000", "对账金额": "4096.00"},
]
SENSITIVE_ORIGINALS = [r["联系方式"] for r in SAMPLE_ROWS] + [r["对账金额"] for r in SAMPLE_ROWS]


def _fresh():
    store_mod.store.reset()
    return {
        "anonym": DataAnonymService(),
        "classification": ClassificationService(),
    }


def _confirm_sensitive_field(s, field_name):
    """登记并确认一个敏感字段分级标签。"""
    label = s["classification"].classify_field(ASSET, field_name, "高", "正则匹配")
    s["classification"].confirm_classification(label["id"])
    return label


def _register_active_rule(s, code, field_path, algorithm="mask", preserve="0"):
    """登记一条脱敏规则并启效，返回规则记录。"""
    entry, missing = s["anonym"].create_entry({
        "规则编号": code,
        "目标字段": field_path,
        "脱敏算法": algorithm,
        "保留位数": preserve,
        "替换字符": "*",
        "适用场景": "交付脱敏",
        "可逆标志": "否",
        "密钥版本": "v1",
    })
    assert not missing
    rule, msg = s["anonym"].run_action(entry["id"], "启效规则")
    assert rule is not None, msg
    return rule


def _setup_rules(s, contact_preserve="7"):
    """准备分级标签与两条已生效规则（联系方式 + 对账金额）。"""
    _confirm_sensitive_field(s, "联系方式")
    _confirm_sensitive_field(s, "对账金额")
    contact = _register_active_rule(
        s, "DATA-D1-CONTACT", f"{ASSET}.联系方式", preserve=contact_preserve,
    )
    amount = _register_active_rule(
        s, "DATA-D1-AMOUNT", f"{ASSET}.对账金额", preserve="0",
    )
    return contact, amount


def _anonym_logs():
    return [r for r in store_mod.store.rows("operation_log")
            if str(r.get("记录编号", "")).startswith("OPER-ANON-")]


# ══════════════════════════════════════════════════════════════════
# 主场景：停机 → 更正规则 → 续做 → 交付与审计核对
# ══════════════════════════════════════════════════════════════════

class TestInterruptResumeWithRuleUpdate:

    def test_interrupt_after_row2_contact_then_resume_with_updated_rule(self):
        s = _fresh()
        contact_rule, _ = _setup_rules(s)

        opened = s["anonym"].open_batch(ASSET, SAMPLE_ROWS)
        assert opened["planned_tasks"] == 6  # 3 行 × 2 个敏感列
        batch_id = opened["batch_id"]

        # 在第二行联系字段处理完、第三行还未开始时停机：
        # 任务顺序为 行1联系 → 行1金额 → 行2联系，处理完 3 个任务即中断
        paused = s["anonym"].run_batch(batch_id, interrupt_after=3)
        assert paused["status"] == "已中断"
        assert paused["delivered_rows"] == [1]  # 行1两个敏感字段都完成才交付
        assert paused["pending_rows"] == [2, 3]
        assert len(paused["receipts"]) == 3
        assert [r["row_no"] for r in paused["receipts"]] == [1, 1, 2]

        # 中断时点：行1联系方式的脱敏结果快照（v1，保留 7 位）
        row1_contact_v1 = paused["records"][0]["联系方式"]
        assert row1_contact_v1 == "1380013****"
        # 行2联系方式已处理（v1），行3还未开始（仍是原值，未交付）
        assert paused["records"][1]["联系方式"] == "1390013****"
        assert paused["records"][2]["联系方式"] == "13700137000"

        # 值班员换一条有效遮盖规则：编号不变，版本 v1 → v2
        rule, msg = s["anonym"].update_masking_rule(contact_rule["id"], {"保留位数": "3"})
        assert rule is not None, msg
        assert rule["规则编号"] == "DATA-D1-CONTACT"
        assert rule["规则版本"] == "v2"

        # 断点续做
        done = s["anonym"].resume_batch(batch_id)
        assert done["status"] == "已完成"
        assert done["delivered_rows"] == [1, 2, 3]
        assert done["failed"] == []

        records = done["records"]
        # 成品里不得出现未经处理的联系方式（也不得有未处理金额）
        for i, row in enumerate(records):
            assert row["联系方式"] != SAMPLE_ROWS[i]["联系方式"]
            assert row["对账金额"] != SAMPLE_ROWS[i]["对账金额"]
            assert row["区域码"] == SAMPLE_ROWS[i]["区域码"]  # 非敏感列不动

        # 断线续做不给已成功字段二次掩码：行1、行2联系方式保持 v1 结果
        assert records[0]["联系方式"] == row1_contact_v1
        assert records[1]["联系方式"] == "1390013****"
        # 第三行在规则更正后处理，采用 v2（保留 3 位）
        assert records[2]["联系方式"] == "137********"
        # 金额规则未更新，三行都按 v1 全掩码
        assert all(row["对账金额"] == "*" * len(SAMPLE_ROWS[i]["对账金额"])
                   for i, row in enumerate(records))

    def test_delivery_audit_by_row_and_version(self):
        s = _fresh()
        contact_rule, _ = _setup_rules(s)
        batch_id = s["anonym"].open_batch(ASSET, SAMPLE_ROWS)["batch_id"]
        s["anonym"].run_batch(batch_id, interrupt_after=3)

        # 中断时点：审计汇总只覆盖已交付的行1
        audit = s["anonym"].delivery_audit(batch_id)
        assert audit["delivered_rows"] == [1]
        assert audit["row_versions"] == {"1": {"对账金额": "v1", "联系方式": "v1"}}

        s["anonym"].update_masking_rule(contact_rule["id"], {"保留位数": "3"})
        s["anonym"].resume_batch(batch_id)

        # 审计员只通过行号和版本即可查明实际交割范围
        audit = s["anonym"].delivery_audit(batch_id)
        assert audit["delivered_rows"] == [1, 2, 3]
        assert audit["pending_rows"] == []
        assert audit["row_versions"] == {
            "1": {"对账金额": "v1", "联系方式": "v1"},
            "2": {"对账金额": "v1", "联系方式": "v1"},
            "3": {"对账金额": "v1", "联系方式": "v2"},
        }
        # 版本 → 交割行范围：v2 只覆盖第三行的联系字段
        assert audit["version_scope"] == {"v1": [1, 2, 3], "v2": [3]}

    def test_logs_carry_row_and_version_without_sensitive_values(self):
        s = _fresh()
        contact_rule, _ = _setup_rules(s)
        batch_id = s["anonym"].open_batch(ASSET, SAMPLE_ROWS)["batch_id"]
        s["anonym"].run_batch(batch_id, interrupt_after=3)
        s["anonym"].update_masking_rule(contact_rule["id"], {"保留位数": "3"})
        s["anonym"].resume_batch(batch_id)

        logs = [r for r in _anonym_logs() if r.get("批次号") == batch_id]
        # 每个字段任务一条行级回执：3 行 × 2 敏感列
        assert len(logs) == 6
        # 日志带行号与规则版本，审查员可按同一规则版本核对每一行
        assert {r["行号"] for r in logs} == {1, 2, 3}
        versions = {r["规则版本"] for r in logs}
        assert versions == {"v1", "v2"}
        row3_contact = [r for r in logs if r["行号"] == 3 and r["目标资产"] == f"{ASSET}.联系方式"]
        assert row3_contact[0]["规则版本"] == "v2"
        # 每条回执带结果摘要，可核对交付值
        assert all(r.get("结果摘要") and r.get("结果长度") for r in logs)

        # 日志不得写入敏感原值：全表扫描所有字段值
        whole_log_table = json.dumps(_anonym_logs(), ensure_ascii=False)
        for original in SENSITIVE_ORIGINALS:
            assert original not in whole_log_table

    def test_recoverable_batches_listed_until_completed(self):
        s = _fresh()
        _setup_rules(s)
        batch_id = s["anonym"].open_batch(ASSET, SAMPLE_ROWS)["batch_id"]
        s["anonym"].run_batch(batch_id, interrupt_after=3)

        # 中断批次保留可核对
        recoverable = s["anonym"].find_recoverable_batches()
        assert [b["batch_id"] for b in recoverable] == [batch_id]
        assert recoverable[0]["status"] == "已中断"
        assert recoverable[0]["delivered_rows"] == [1]

        # 续做完成后不再列入待恢复
        s["anonym"].resume_batch(batch_id)
        assert s["anonym"].find_recoverable_batches() == []


# ══════════════════════════════════════════════════════════════════
# 失败批次：规则缺失 → 保留可核对 → 修正后恢复
# ══════════════════════════════════════════════════════════════════

class TestFailedBatchRecovery:

    def test_failed_batch_preserved_and_recovered_after_rule_fix(self):
        s = _fresh()
        _confirm_sensitive_field(s, "联系方式")
        _confirm_sensitive_field(s, "对账金额")
        # 只配联系方式规则，对账金额故意缺失已生效规则
        _register_active_rule(s, "DATA-D2-CONTACT", f"{ASSET}.联系方式", preserve="3")

        batch_id = s["anonym"].open_batch(ASSET, SAMPLE_ROWS)["batch_id"]
        report = s["anonym"].run_batch(batch_id)
        assert report["status"] == "部分失败"
        # 每行都缺金额字段，无一整行可交付
        assert report["delivered_rows"] == []
        # 失败批次保留可核对：行号、字段、原因齐全
        assert len(report["failed"]) == 3
        assert {f["row_no"] for f in report["failed"]} == {1, 2, 3}
        assert all(f["field"] == "对账金额" for f in report["failed"])
        assert all("无已生效" in f["reason"] for f in report["failed"])
        assert s["anonym"].find_recoverable_batches()[0]["failed_tasks"] == 3

        # 值班员补上有效规则后续做：失败任务自动重试
        _register_active_rule(s, "DATA-D2-AMOUNT", f"{ASSET}.对账金额", preserve="0")
        done = s["anonym"].resume_batch(batch_id)
        assert done["status"] == "已完成"
        assert done["delivered_rows"] == [1, 2, 3]
        assert done["failed"] == []
        for i, row in enumerate(done["records"]):
            assert row["联系方式"] != SAMPLE_ROWS[i]["联系方式"]
            assert row["对账金额"] != SAMPLE_ROWS[i]["对账金额"]

        # 失败回执仍留在批次历史里可核对，且失败日志不含原值
        history = [r for r in done["receipts"] if r["status"] == "失败"]
        assert len(history) == 3
        failed_logs = [r for r in _anonym_logs() if r.get("处理结果") == "失败"]
        assert len(failed_logs) == 3
        assert all(l["abnormal"] for l in failed_logs)
        whole_log_table = json.dumps(_anonym_logs(), ensure_ascii=False)
        for original in SENSITIVE_ORIGINALS:
            assert original not in whole_log_table

    def test_unknown_algorithm_fails_instead_of_leaking_raw_value(self):
        s = _fresh()
        _confirm_sensitive_field(s, "联系方式")
        _confirm_sensitive_field(s, "对账金额")
        _register_active_rule(s, "DATA-D3-CONTACT", f"{ASSET}.联系方式",
                              algorithm="不存在的算法", preserve="3")
        _register_active_rule(s, "DATA-D3-AMOUNT", f"{ASSET}.对账金额", preserve="0")

        batch_id = s["anonym"].open_batch(ASSET, SAMPLE_ROWS)["batch_id"]
        report = s["anonym"].run_batch(batch_id)
        assert report["status"] == "部分失败"
        # 未识别算法按失败处理，联系方式原值不得流入成品
        assert report["delivered_rows"] == []
        assert all("未知脱敏算法" in f["reason"]
                   for f in report["failed"] if f["field"] == "联系方式")

        # 更正为有效遮盖规则（v1 → v2）后恢复
        contact = store_mod.store.find_by_field("data_anonym", "规则编号", "DATA-D3-CONTACT")[0]
        s["anonym"].update_masking_rule(contact["id"], {"脱敏算法": "掩码", "保留位数": "3"})
        done = s["anonym"].resume_batch(batch_id)
        assert done["status"] == "已完成"
        for i, row in enumerate(done["records"]):
            assert row["联系方式"] != SAMPLE_ROWS[i]["联系方式"]
        # 更正后处理的联系方式全部为 v2
        audit = s["anonym"].delivery_audit(batch_id)
        assert all(v["联系方式"] == "v2" for v in audit["row_versions"].values())


# ══════════════════════════════════════════════════════════════════
# 兼容性：旧接口与已有规则编号
# ══════════════════════════════════════════════════════════════════

class TestCompatibility:

    def test_anonymize_dataset_keeps_legacy_signature(self):
        s = _fresh()
        _setup_rules(s)
        records, fields = s["anonym"].anonymize_dataset(ASSET, SAMPLE_ROWS)
        assert len(records) == 3
        for i, row in enumerate(records):
            assert row["联系方式"] != SAMPLE_ROWS[i]["联系方式"]
            assert row["对账金额"] != SAMPLE_ROWS[i]["对账金额"]
        assert set(fields) == {"DATA-D1-CONTACT", "DATA-D1-AMOUNT"}

    def test_resume_compatible_with_existing_rule_code(self):
        """既有规则（含种子数据风格、无版本字段）更新后编号不变，恢复处理按编号解析。"""
        s = _fresh()
        seed_rule = store_mod.store.rows("data_anonym")[0]
        assert seed_rule["规则编号"] == "DATA-0001"
        assert "规则版本" not in seed_rule  # 既有规则没有版本字段，按 v1 处理

        rule, msg = s["anonym"].update_masking_rule(seed_rule["id"], {"保留位数": "2"})
        assert rule is not None, msg
        assert rule["规则编号"] == "DATA-0001"  # 编号兼容不变
        assert rule["规则版本"] == "v2"  # 版本自动递增

        # 再次更新继续递增
        rule, _ = s["anonym"].update_masking_rule(seed_rule["id"], {"保留位数": "1"})
        assert rule["规则版本"] == "v3"

    def test_completed_batch_is_idempotent_on_rerun(self):
        s = _fresh()
        _setup_rules(s)
        batch_id = s["anonym"].open_batch(ASSET, SAMPLE_ROWS)["batch_id"]
        first = s["anonym"].run_batch(batch_id)
        assert first["status"] == "已完成"
        receipt_count = len(first["receipts"])

        # 重复执行已完成批次：直接返回报告，不产生新回执、不二次掩码
        again = s["anonym"].run_batch(batch_id)
        assert again["status"] == "已完成"
        assert len(again["receipts"]) == receipt_count
        assert again["records"] == first["records"]
