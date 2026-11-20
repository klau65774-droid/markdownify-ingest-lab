from concurrent.futures import ThreadPoolExecutor

import pytest
from bs4 import BeautifulSoup, Tag

from markdownify import MarkdownConverter, _upstream_v124, markdownify
from markdownify.baseline import baseline_markdownify
from markdownify.guard import BudgetExceededError
from markdownify.ingest import ingest_html
from markdownify.structural import markdown_table_metrics


def test_span_grid_keeps_covered_columns_and_places_next_cells_at_the_right_index():
    html = (
        '<table><caption>Totals</caption><thead><tr><th rowspan="2">Region</th>'
        '<th colspan="2">Visitors</th></tr><tr><th>Mobile</th><th>Desktop</th></tr></thead>'
        '<tbody><tr><td rowspan="2">East</td><td colspan="2">A | B</td></tr>'
        '<tr><td>7</td><td>9</td></tr></tbody></table>'
    )
    result = ingest_html(html, compare_baseline=True)
    assert result.markdown.splitlines() == [
        "Totals", "", "| Region | Visitors |  |", "| --- | --- | --- |",
        "|  | Mobile | Desktop |", r"| East | A \| B |  |", "|  | 7 | 9 |",
    ]
    assert result.cells_expanded == 4
    assert markdown_table_metrics(result.markdown) == ([3, 3, 3, 3, 3], True)
    assert not result.baseline.table_alignment_valid


def test_grid_checks_all_columns_in_a_span_before_placing_it():
    html = (
        "<table><tr><th>First</th><th rowspan='2'>Second</th><th>Third</th></tr>"
        "<tr><td colspan='2'>Wide</td></tr></table>"
    )
    markdown = markdownify(html, normalize_tables=True)
    assert markdown.splitlines()[-1] == "|  |  | Wide |  |"
    assert markdown_table_metrics(markdown) == ([4, 4, 4], True)


def test_invalid_and_huge_spans_are_clamped_and_blank_rows_padded():
    html = (
        "<table><tr><th>H</th></tr><tr><td rowspan='0' colspan='-2'>One</td></tr>"
        "<tr><td colspan='" + "9" * 6000 + "' rowspan='1000'>Wide</td></tr><tr></tr></table>"
    )
    result = ingest_html(html)
    widths, aligned = markdown_table_metrics(result.markdown)
    assert aligned and widths == [32] * 5
    assert result.cells_expanded == 63


def test_grid_budget_bounds_rectangular_padding():
    html = "<table><tr>" + "<th colspan='32'>Wide</th>" * 80 + "</tr>"
    html += "<tr><td>Value</td></tr>" * 100 + "</table>"
    with pytest.raises(BudgetExceededError, match="max_nodes"):
        ingest_html(html)


def test_nested_tables_do_not_add_outer_columns():
    html = (
        "<table><tr><th>First <table><tr><th>X</th><th>Y</th></tr></table></th>"
        "<th>Second</th></tr><tr><td>A</td><td>B</td></tr></table>"
    )
    for normalized in (False, True):
        markdown = markdownify(html, normalize_tables=normalized)
        assert "X" in markdown and "Y" in markdown
        assert markdown_table_metrics(markdown) == ([2, 2, 2], True)
    assert baseline_markdownify(html) != markdownify(html)


def test_pipes_respect_escape_parity_and_inline_code():
    html = r"<table><tr><th>A \| B</th><th>C \\| D</th><th><code>E | F</code></th></tr></table>"
    assert markdownify(html).splitlines()[0] == r"| A \| B | C \\\| D | `E \| F` |"
    assert markdown_table_metrics(markdownify(html)) == ([3, 3], True)
    assert markdown_table_metrics(baseline_markdownify(html)) == ([5, 3], False)


def test_table_metrics_exclude_fences_and_preserve_per_table_widths():
    markdown = (
        "```md\n| Not | an | actual table |\n| --- |\n```\n\n"
        "> | Quoted | Table |\n> | :---- | ---: |\n> | A | B |\n\n"
        "Only column\n\n| Single |\n| --- |\n| Content |\n\n"
        "A | B\n---|---\nX | Y"
    )
    assert markdown_table_metrics(markdown) == ([2, 2, 2, 1, 1, 1, 2, 2, 2], True)
    assert markdown_table_metrics("A | B\n---|---\nX | Y | Z") == ([2, 2, 3], False)


@pytest.mark.parametrize(
    ("attrs", "language"),
    [
        ('class="hljs language-py"', "python"),
        ('class="lang-js"', "javascript"),
        ('class="highlight-source-ts"', "typescript"),
        ('class="brush: c++"', "cpp"),
        ('data-language="yml"', "yaml"),
        ('data-lang="zsh"', "bash"),
    ],
)
def test_language_hints_are_inferred_in_enhanced_modes(attrs, language):
    html = f"<pre><code {attrs}>body</code></pre>"
    assert ingest_html(html).markdown == f"```{language}\nbody\n```"
    assert markdownify(html) == "```\nbody\n```"
    assert ingest_html(html, infer_code_language=False).markdown == markdownify(html)


def test_code_language_precedence_and_longer_fence():
    html = '<pre data-lang="js"><code class="language-py">body</code></pre>'
    assert markdownify(html, infer_code_language=True).startswith("```javascript")
    assert markdownify(html, infer_code_language=True, code_language="rust").startswith("```rust")
    assert markdownify(
        html, infer_code_language=True, code_language="rust", code_language_callback=lambda _: "yaml",
    ).startswith("```yaml")
    assert markdownify(
        html, infer_code_language=True, code_language_callback=lambda _: None,
    ).startswith("```javascript")
    assert ingest_html("<pre>```\n| A | B |\n| --- |</pre>").markdown.startswith("````\n")


def test_ordered_list_traversal_uses_precomputed_sibling_ordinals(monkeypatch):
    def unexpected(*_args, **_kwargs):
        pytest.fail("Recursive conversion must not search earlier list siblings")

    monkeypatch.setattr(Tag, "find_previous_siblings", unexpected)
    monkeypatch.setattr(Tag, "previous_siblings", property(unexpected))
    html = "<ol start='4'><li>Start<ol start='7'><li>Nested</li></ol></li><li></li><li>Finish</li></ol>"
    markdown = markdownify(html)
    assert markdown.splitlines() == ["4. Start", "   7. Nested", "6. Finish"]
    many = "<ol>" + "<li>Item</li>" * 1500 + "</ol>"
    lines = markdownify(many).splitlines()
    assert len(lines) == 1500 and lines[-1] == "1500. Item"
    rich = "<ol>" + "<li><em>Item</em></li>" * 1500 + "</ol>"
    assert markdownify(rich).splitlines()[-1] == "1500. *Item*"


def test_converter_reuse_keeps_context_local_to_each_soup():
    converter = MarkdownConverter()
    soups = [
        BeautifulSoup(f"<ol start='{index}'><li>First</li><li>Next</li></ol>", "html.parser")
        for index in range(1, 17)
    ]
    with ThreadPoolExecutor(max_workers=4) as executor:
        outputs = list(executor.map(converter.convert_soup, soups))
    assert outputs == [f"{index}. First\n{index + 1}. Next" for index in range(1, 17)]


@pytest.mark.parametrize("options", [
    {}, {"strip_document": None}, {"strip_document": "lstrip"}, {"strip_document": "rstrip"},
    {"escape_misc": True}, {"escape_underscores": False, "escape_asterisks": False}, {"wrap": True},
])
def test_plain_list_renderer_preserves_upstream_options_and_blank_items(options):
    html = (
        "\n<OL start='009'>\n<li>   First_* item  </li><li></li>\t<li> </li>"
        "<li> 多行 \r\n  内容  >  词 </li><li> # Last | [label] </li>\n</ol>  "
    )
    result = markdownify(html, **options)
    assert result == _upstream_v124.markdownify(html, **options)
    assert result == MarkdownConverter(**options).convert_soup(BeautifulSoup(html, "html.parser"))


@pytest.mark.parametrize("html", [
    "<ol><li>A &amp; B</li><li>More</li></ol>",
    "<ol><li>One<ul><li>Nested</li></ul></li><li>Two</li></ol>",
    "<ol><li>One</li><!-- gap --><li>Two</li></ol>",
    "<ol><li>Unclosed<li>Next</ol>",
    '<main><ol start="4"><li><em>Rich</em></li><li>Text</li></ol></main>',
])
def test_ordered_lists_requiring_html_parsing_follow_dom_semantics(html):
    assert markdownify(html) == baseline_markdownify(html)


def test_plain_lists_respect_custom_converters_and_tag_filters():
    class CustomConverter(MarkdownConverter):
        def convert_li(self, el, text, parent_tags):
            return f"<{text}>"

    html = "<ol><li>One</li><li>Two</li></ol>"
    assert CustomConverter().convert(html) == "<One><Two>"
    assert markdownify(html, strip=["li", "ol"]) == "OneTwo"


@pytest.mark.parametrize("container", ["ol", "ul"])
def test_table_and_code_example_inside_a_quoted_list(container):
    table = "<table><tr><th>One</th><th>Two</th></tr><tr><td>A</td><td>B</td></tr></table>"
    example = "<pre>| sample | code |\n| --- |</pre>"
    html = f"<blockquote><{container}><li>{table}</li><li>{example}</li></{container}></blockquote>"
    result = ingest_html(html)
    assert result.table_alignment_valid
    assert markdown_table_metrics(result.markdown) == ([2, 2, 2], True)


def test_span_width_handles_non_ascii_decimal_leading_zeros():
    html = '<table><tr><th colspan="' + "\u0e50" * 30 + '๒">Heading</th></tr></table>'
    result = ingest_html(html)
    assert result.cells_expanded == 1
    assert markdown_table_metrics(result.markdown) == ([2, 2], True)
