# coding=utf-8
import json, os
import csv
from Utils.logs import print_notice
from sqlalchemy import Column, Boolean, Integer, String, JSON


from CodePropertyGraph.db import Base, session_factory


class CSVGraph(Base):
    """ CSV graph class.
        This is the gorm class to handle cpg graph generated in csv file by phpjoern.
        Graph info will be store in table cpg.
    """
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

        cpg = CSVGraph(file_path, vuln_lines)
        session = session_factory()
        session.add(cpg)
        session.commit()

        # Add nodes to db
        print_notice(f'Adding nodes and edges from CPG no.{cpg.id} to database...')
        node_lst = CSVNode.getNodesFromCSV('./nodes.csv', cpg.id, vuln_lines)
        CSVNode.addNodes(node_lst)

        # Add edges to db
        edge_lst = CSVEdge.getEdgesFromCSV('./rels.csv', cpg.id)
        edge_lst += CSVEdge.getEdgesFromCSV('./cpg_edges.csv', cpg.id)
        CSVEdge.addEdges(edge_lst)
        session.close()
        return cpg


class CSVEdge(Base):
    """ CSV Edge class.
        This is the gorm class to handle cpg edge generated in csv file by phpjoern.
        Edge info will be store in table edge.
    """
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
                    edge = CSVEdge(row[0], row[1], row[2], cpg_id)
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
        edge_lst = session.query(CSVEdge).where(CSVEdge.cpg_id == cpg_id)
        session.close()
        return edge_lst


class CSVNode(Base):
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
                    labels = CSVNodeLabels(row[1], row[2], row[3], row[4], row[5], row[6],
                                    row[7], row[8], row[9], row[10], row[11], row[12])
                    is_vuln = False

                    if labels.lineno and labels.lineno in vuln_lines:
                        is_vuln = True
                    node = CSVNode(row[0], cpg_id, labels, is_vuln)
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
        node_lst = session.query(CSVNode).where(CSVNode.cpg_id == cpg_id)
        session.close()
        return node_lst


class CSVNodeLabels(dict):
    """CSV Node Label class."""

    def __init__(self,
                 label, nodetype, flags, lineno,
                 code, childnum, funcid, classname,
                 namespace, endlineno, name, doccomment):
        """Initialize Labels instance.

        Args:
            label:
            nodetype:
            flags:
            lineno:
            code:
            childnum:
            funcid:
            classname:
            namespace:
            endlineno:
            name:
            doccomment:
        """
        dict.__init__(self, labels=label,
                      nodetype=nodetype,
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

        self.label = label
        self.nodetype = nodetype
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
