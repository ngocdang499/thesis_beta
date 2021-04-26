# coding=utf-8
import json, os
import csv
from Utils.logs import print_notice
from sqlalchemy import Column, Boolean, Integer, String, JSON


from CodePropertyGraph.db import Base, session_factory


class CPG(Base):
    __tablename__ = 'cpg'

    id = Column(Integer, primary_key=True)
    file_path = Column(String)
    vuln_lines = Column(String)

    def __init__(self, file_path, vuln_line_lst):
        self.file_path = file_path
        self.vuln_lines = ','.join([str(l) for l in vuln_line_lst])

    @staticmethod
    def generate_CPG(file_path, vuln_lines=[]):
        os.system('./tools/phpjoern/php2ast -f neo4j %s' % file_path)
        os.system('./tools/joern/phpast2cpg ./nodes.csv ./rels.csv')

        cpg = CPG(file_path, vuln_lines)
        session = session_factory()
        session.add(cpg)
        session.commit()
        # Add nodes to db
        print_notice(f'Adding nodes and edges from CPG no.{cpg.id} to database...')
        node_lst = Node.getNodesFromCSV('./nodes.csv', cpg.id, vuln_lines)
        Node.addNodes(node_lst)

        # Add edges to db
        edge_lst = Edge.getEdgesFromCSV('./rels.csv', cpg.id)
        edge_lst += Edge.getEdgesFromCSV('./cpg_edges.csv', cpg.id)
        Edge.addEdges(edge_lst)
        session.close()
        return cpg


class Edge(Base):
    __tablename__ = 'edge'

    id = Column(Integer, primary_key=True)
    in_vertex = Column(Integer)
    out_vertex = Column(Integer)
    labels = Column(String)
    cpg_id = Column(Integer)

    def __init__(self, in_vertex, out_vertex, labels, cpg_id):
        self.in_vertex = in_vertex
        self.out_vertex = out_vertex
        self.cpg_id = cpg_id
        self.labels = labels

    @staticmethod
    def getEdgesFromCSV(filepath, cpg_id):
        edge_lst = []
        with open(filepath) as csv_file:
            csv_reader = csv.reader(csv_file, delimiter=',')
            line_count = 0
            for row in csv_reader:
                if line_count == 0:
                    line_count += 1
                else:
                    edge = Edge(row[0], row[1], row[2], cpg_id)
                    edge_lst.append(edge)
                    line_count += 1
        return edge_lst

    @staticmethod
    def addEdges(edge_lst):
        session = session_factory()
        session.bulk_save_objects(edge_lst)
        session.commit()
        session.close()

    @staticmethod
    def getEdges(cpg_id):
        session = session_factory()
        edge_lst = session.query(Edge).where(Edge.cpg_id == cpg_id)
        session.close()
        return edge_lst


class Node(Base):
    __tablename__ = 'node'

    id = Column(Integer, primary_key=True)
    node_id = Column(Integer)
    cpg_id = Column(Integer)
    labels = Column(JSON)
    is_vuln = Column(Boolean)

    def __init__(self, node_id, cpg_id, labels, is_vuln):
        self.node_id = node_id
        self.cpg_id = cpg_id
        self.labels = json.dumps(labels)
        self.is_vuln = is_vuln

    @staticmethod
    def getNodesFromCSV(filepath, cpg_id, vuln_lines):
        node_lst = []
        with open(filepath) as csv_file:
            csv_reader = csv.reader(csv_file, delimiter=',')
            line_count = 0
            for row in csv_reader:
                if line_count == 0:
                    line_count += 1
                else:
                    labels = Labels(row[1], row[2], row[3], row[4], row[5], row[6],
                                    row[7], row[8], row[9], row[10], row[11], row[12])
                    is_vuln = False

                    if labels.lineno and labels.lineno in vuln_lines:
                        is_vuln = True
                    node = Node(row[0], cpg_id, labels, is_vuln)
                    node_lst.append(node)
                    line_count += 1
        return node_lst

    @staticmethod
    def addNodes(node_lst):
        session = session_factory()
        session.bulk_save_objects(node_lst)
        session.commit()
        session.close()

    @staticmethod
    def getNodes(cpg_id):
        session = session_factory()
        node_lst = session.query(Node).where(Node.cpg_id == cpg_id)
        session.close()
        return node_lst


class Labels(dict):
    labels = ""
    type = ""
    flags = []
    lineno = None
    code = ""
    childnum = None
    funcid = None
    classname = ""
    namespace = ""
    endlineno = None
    name = ""
    doccomment = ""

    def __init__(self, labels, type, flags, lineno, code, childnum, funcid, classname, namespace, endlineno, name,
                 doccomment):
        dict.__init__(self, labels=labels,
                      type=type,
                      flags=flags,
                      lineno=int(lineno) if lineno else None,
                      code=code,
                      childnum=childnum,
                      funcid=funcid,
                      classname=classname,
                      namespace=namespace,
                      endlineno=endlineno,
                      name=name,
                      doccomment=doccomment)
        self.labels = labels
        self.type = type
        self.flags = flags
        self.lineno = int(lineno) if lineno else None
        self.code = code
        self.childnum = childnum
        self.funcid = funcid
        self.classname = classname
        self.namespace = namespace
        self.endlineno = endlineno
        self.name = name
        self.doccomment = doccomment
#

#
#     @staticmethod
#     def store_CPG(self):
#         """
#         connect to db and store graph id, file_path, vulnType, vulnLine,
#         nodes, edges.
#         :return:
#         """
#         pass
#
#     def get_CPG(self):
#         """
#         get CPG from DB
#         :return:
#         """
#         pass
#
#
# class Node:
#     def __init__(self,nodeId, labels, graphId, isVuln):
#         node_id      = nodeId
#         graph_id     = graphId
#         labels       = labels
#         is_vuln      = isVuln
#
#
# class Edge:
#     def __init__(self, inV, outV, labels, graphId):
#         in_vertex   = inV
#         out_vertex  = outV
#         labels      = labels
#         graph_id    = graphId
