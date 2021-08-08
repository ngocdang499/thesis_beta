import pandas as pd
import os
import csv

from src.dataset import *
from src.code_property_graph.cpg import *
from src.code_property_graph.neo4j_db import *


def import_graph_to_neo4j(filepath):
    # regenerate cpg
    run_phpjoern(filepath)
    # os.system('/home/mn404/Documents/Thesis/Project/tools/phpjoern/php2ast -f neo4j %s' % filepath)
    # os.system('/home/mn404/Documents/Thesis/Project/tools/joern/phpast2cpg ./csvfiles/nodes.csv ./csvfiles/rels.csv')

    # import graph to neo4j
    conn = Neo4jConnection()

    # remove leftover node
    query_string = """
    MATCH (n)
    DETACH DELETE n;
    """
    conn.query(query_string, db='neo4j')

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
    LOAD CSV WITH HEADERS FROM 'file:///cpg_edges.csv' AS row
    MATCH (out_node:Node {id: row.start})
    MATCH (in_node:Node {id: row.end})
    CREATE (out_node)-[:CPG {type: row.type, var: row.var}]->(in_node)
    '''
    conn.query(query_string, db='neo4j')
    conn.close()


def generate_features_from_code(frequent_patterns_set):
    feature_vector = []
    for dfscode in frequent_patterns_set:
        match_clause = list()
        where_clause = list()
        vertices = dict()
        for e in dfscode:
            frm, to, (vlb1, elb, vlb2) = e["frm"], e["to"], e["vevlb"]
            if frm not in vertices:
                vertices[frm] = vlb1
            if to not in vertices:
                vertices[to] = vlb2
            if ':' in elb:
                attb = elb.split(":")
                edge_type = "CPG"
                if attb[1] != "":
                    match_clause.append(f'(v{frm})<-[:{edge_type} {{type: "{attb[0]}", var: "{attb[1]}"}}]-(v{to})')
                else:
                    match_clause.append(f'(v{frm})<-[:{edge_type} {{type: "{attb[0]}"}}]-(v{to})')
            else:
                edge_type = "AST"
                match_clause.append(f'(v{frm})<-[:{edge_type} {{type: "{elb}"}}]-(v{to})')
        for id, type in vertices.items():
            type = type.split(":")
            if type[2] != "":
                type[2] = type[2].replace("\"", "")
                where_clause.append(f'v{id}.type = "{type[1]}" AND v{id}.labels = "{type[0]}" AND v{id}.code = "{type[2]}"')
            else:
                where_clause.append(f'v{id}.type = "{type[1]}" AND v{id}.labels = "{type[0]}"')
        query_string = 'MATCH {0} WHERE {1} RETURN v0'.format(', '.join(match_clause), ' AND '.join(where_clause))
        conn = Neo4jConnection()

        res = conn.query(query_string, db='neo4j')

        feature_vector.append(len(res))
    return feature_vector


def write_features_to_CSV(features_set):
    print(features_set)
    with open('csvfiles/data_features.csv', mode='a') as employee_file:
        print("tmp")
        for vector in features_set:
            print(vector)
            employee_writer = csv.writer(employee_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
            employee_writer.writerow(vector)


def create_features_file(frequent_patterns_set, cpg_lst, vuln):
    # cpg_lst = CSVGraph.getCPGs()
    feature_set = []
    for g in cpg_lst:
        import_graph_to_neo4j(os.path.join("/home/mn404/Documents/Project", g.file_path))
        feature_vector = generate_features_from_code(frequent_patterns_set)
        isVuln = 0
        if g.vuln_type == vuln:
            isVuln = 1
        feature_vector.append(isVuln)
        feature_set.append(feature_vector)
    write_features_to_CSV(feature_set)






