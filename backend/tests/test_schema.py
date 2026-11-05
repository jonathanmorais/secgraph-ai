from graphsec.graph.schema import NODE_LABELS, RELATIONSHIPS, schema_as_text


def test_schema_text_includes_all_labels():
    text = schema_as_text()
    for label in NODE_LABELS:
        assert label in text


def test_schema_text_includes_relationships():
    text = schema_as_text()
    for rel, *_ in RELATIONSHIPS:
        assert rel in text
