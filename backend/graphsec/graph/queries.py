"""Reusable Cypher queries for common operations."""

PUBLIC_S3_BUCKETS = """
MATCH (b:S3Bucket {is_public: true})
RETURN b.bucket_name AS bucket, b.region AS region
"""

USERS_WITHOUT_MFA = """
MATCH (u:IAMUser {has_mfa: false})
RETURN u.user_name AS user_name, u.arn AS arn, u.last_used AS last_used
"""

EXPOSED_EC2_SSH = """
MATCH (ec2:EC2Instance)-[:MEMBER_OF]->(sg:SecurityGroup)
WHERE ec2.public_ip IS NOT NULL AND sg.exposes_ssh_world = true
RETURN ec2.instance_id AS instance_id, ec2.public_ip AS public_ip, sg.group_id AS sg
"""

TOP_CRITICAL_FINDINGS = """
MATCH (r)-[:HAS_FINDING]->(f:Finding)
WHERE f.severity = 'CRITICAL'
RETURN labels(r)[0] AS tipo, r.arn AS recurso, f.title AS title, f.source AS source
ORDER BY f.severity DESC
LIMIT $limit
"""

FULL_GRAPH = """
MATCH (n)
OPTIONAL MATCH (n)-[r]->(m)
RETURN n, r, m
LIMIT $limit
"""

NODE_NEIGHBORHOOD = """
MATCH (n)-[r*1..$depth]-(m)
WHERE elementId(n) = $node_id
RETURN n, r, m
"""
