import pandas as pd
import os

from src.dataset import *
from src.code_property_graph.postgre_db import *
from src.code_property_graph.neo4j_db import *


def import_graph_to_neo4j(filepath):
    # regenerate cpg
    os.system('../../tools/phpjoern/php2ast -f neo4j %s' % "/home/mn404/Documents/Thesis/Project/data/NVD/PHP/SQLi/CVE-2006-1049/app/administrator/includes/admin.php")
    os.system('../../tools/joern/phpast2cpg ./csvfiles/nodes.csv ./csvfiles/rels.csv')

    # import graph to neo4j
    conn = Neo4jConnection(uri="neo4j://172.19.0.2:7687", user="neo4j", pwd="bitnami")

    # load nodes.csv file
    query_string = """
    LOAD CSV WITH HEADERS FROM 'file:///nodes.csv' AS row
    CREATE (:Node {id: row.id, labels: row.labels, type: row.type, flags: row.flags, lineno: row.lineno, code: row.code, \
    childnum: row.childnum, funcid: row.funcid, classname: row.classname, namespace: row.namespace, endlineno: row.endlineno, \
    name: row.name, doccomment: row.doccomment});
    """
    conn.query(query_string, db='neo4j')

    # load edges.csv file
    query_string = '''
    LOAD CSV WITH HEADERS FROM 'file:///rels.csv' AS row
    MATCH (out_node:Node {id: row.start})
    MATCH (in_node:Node {id: row.end})
    CREATE (out_node)-[:AST {type: row.type}]->(in_node)
    '''
    conn.query(query_string, db='neo4j')

    # load cpg_edges.csv file
    query_string = '''
    LOAD CSV WITH HEADERS FROM 'file:///rels.csv' AS row
    MATCH (out_node:Node {id: row.start})
    MATCH (in_node:Node {id: row.end})
    CREATE (out_node)-[:CPG {type: row.type, var: row.var}]->(in_node)
    '''
    conn.query(query_string, db='neo4j')
    conn.close()


def generate_features_from_code(frequent_patterns_set):
    # Write to CSV
    feature_vector = []
    for dfscode in frequent_patterns_set:
        match_clause = list()
        where_clause = list()
        vertices = dict()
        for e in dfscode:
            frm, to, (vlb1, elb, vlb2) = e.frm, e.to, e.vevlb
            if frm not in vertices:
                vertices[frm] = vlb1
            if to not in vertices:
                vertices[to] = vlb2
            edge_type = "AST"
            if ':' in elb:
                edge_type = "CPG"
            match_clause.append(f'(v{frm})-[:{edge_type} {{type: "{elb}"}}]->(v{to})')
        for id, type in vertices.items():
            type = type.split(":")
            where_clause.append(f'v{id}.type = "{type[0]}"')
        query_string = 'MATCH {0} WHERE {1} RETURN count(v0)'.format(', '.join(match_clause), ' AND '.join(where_clause))

        conn = Neo4jConnection(uri="neo4j://172.19.0.2:7687", user="neo4j", pwd="bitnami")
        res = conn.query(query_string, db='neo4j')
        print("query sub graph", query_string)
        feature_vector.append(res)










