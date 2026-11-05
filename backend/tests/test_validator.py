import pytest
from graphsec.chat.validator import CypherValidationError, extract_cypher, validate


def test_validate_ok():
    assert validate("MATCH (n) RETURN n LIMIT 1") == "MATCH (n) RETURN n LIMIT 1"


@pytest.mark.parametrize("q", [
    "CREATE (n:Foo)",
    "MATCH (n) DELETE n",
    "MERGE (n:X)",
    "MATCH (n) SET n.x = 1",
    "MATCH (n) REMOVE n.x",
    "DROP INDEX ON :Foo(x)",
])
def test_forbidden_keywords(q):
    with pytest.raises(CypherValidationError):
        validate(q)


def test_empty():
    with pytest.raises(CypherValidationError):
        validate("")


def test_no_match_return():
    with pytest.raises(CypherValidationError):
        validate("WITH 1 AS x")


def test_extract_cypher():
    text = "aqui vai:\n```cypher\nMATCH (n) RETURN n\n```\nfim"
    assert extract_cypher(text) == "MATCH (n) RETURN n"


def test_extract_cypher_missing():
    with pytest.raises(CypherValidationError):
        extract_cypher("sem bloco de codigo")
