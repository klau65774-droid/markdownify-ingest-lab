"""Ordered content assertions on documents independent of the demo benchmark."""

import pytest

from markdownify.ingest import ingest_html


@pytest.mark.parametrize("policy", ["clean_rag", "strict_guard"])
@pytest.mark.parametrize(("html", "required"), [
    pytest.param(
        "<nav>All articles</nav><main><h1>Database recovery</h1><ol>"
        "<li>Create a backup.</li><li>Restore to a test database.</li><li>Check the record counts.</li>"
        "</ol></main>",
        ("Database recovery", "Create a backup.", "Restore to a test database.", "Check the record counts."),
        id="en-recovery",
    ),
    pytest.param(
        "<article><h1>API authentication</h1><h2>Bearer authentication</h2>"
        "<p>Bearer tokens expire after an hour.</p><p>Renew before the next request.</p></article>",
        ("API authentication", "Bearer authentication", "Bearer tokens expire after an hour.",
         "Renew before the next request."),
        id="en-authentication",
    ),
    pytest.param(
        "<article><h1>Release checklist</h1><p><strong>Review the draft.</strong><br>"
        '<a href="/tests">Run the integration tests.</a><br>Publish the release notes.</p></article>',
        ("Release checklist", "Review the draft.", "Run the integration tests.", "Publish the release notes."),
        id="en-release",
    ),
    pytest.param(
        "<main><h1>Support hours</h1><table><tr><th>Office</th><th>Opens</th></tr>"
        "<tr><td>Berlin</td><td>08:00</td></tr><tr><td>Taipei</td><td>09:00</td></tr></table></main>",
        ("Support hours", "Office", "Berlin", "Taipei"),
        id="en-schedule",
    ),
    pytest.param(
        "<main><h1>迁移手册</h1><ol><li>先导出数据。</li><li>再导入测试库。</li>"
        "<li>最后核对记录数。</li></ol></main><footer>站点信息</footer>",
        ("迁移手册", "先导出数据。", "再导入测试库。", "最后核对记录数。"),
        id="zh-migration",
    ),
    pytest.param(
        "<article><header><h1>设备验收</h1></header><p>检查设备外观。</p><p>连接测试电源。</p>"
        '<p>记录<a href="/inspection">验收结果</a>。</p></article>',
        ("设备验收", "检查设备外观。", "连接测试电源。", "验收结果"),
        id="zh-inspection",
    ),
    pytest.param(
        '<main><h1>采样记录</h1><div class="site-footer">订阅站点更新</div><p>填写采样日期。</p>'
        "<p>记录样本编号。</p><p>复核保存位置。</p></main>",
        ("采样记录", "填写采样日期。", "记录样本编号。", "复核保存位置。"),
        id="zh-sampling",
    ),
    pytest.param(
        "<article><h1>费用报销</h1><p>收集票据。<br><strong>填写申请单。</strong><br>"
        "提交给审核人员。</p></article>",
        ("费用报销", "收集票据。", "填写申请单。", "提交给审核人员。"),
        id="zh-expenses",
    ),
])
def test_required_content_is_retained_in_order(policy, html, required):
    markdown = ingest_html(html, policy=policy).markdown
    cursor = 0
    for fragment in required:
        position = markdown.find(fragment, cursor)
        assert position >= 0, f"{fragment!r} missing or out of order in {markdown!r}"
        cursor = position + len(fragment)
