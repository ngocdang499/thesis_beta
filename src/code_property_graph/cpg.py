# coding=utf-8
import os
import csv
from src.utils.logs import print_notice
from src.utils.tools import run_phpjoern
from sqlalchemy import Column, Boolean, Integer, String, and_

from src.code_property_graph.postgre_db import Base, session_factory


class CSVGraph(Base):
    """ CSV graph class.
        This is the gorm class to handle cpg graph generated in csv file by phpjoern.
        Graph info will be store in table cpg.
    """
    __tablename__ = 'cpg'

    id = Column(Integer, primary_key=True)
    file_path = Column(String)
    vuln_lines = Column(String)
    vuln_type = Column(String)
    set_type = Column(String)  # training / tuning / testing set

    def __init__(self, file_path, vuln_type, set_type, vuln_line_lst):
        self.file_path = file_path
        self.vuln_lines = ','.join([str(line) for line in vuln_line_lst])
        self.vuln_type = vuln_type if len(self.vuln_lines) > 0 else "Safe_" + vuln_type
        self.set_type = set_type

    @staticmethod
    def generate_CPG(file_path, vuln_type, set_type, vuln_lines=[]):
        run_phpjoern(file_path)

        cpg = CSVGraph(file_path, vuln_type, set_type, vuln_lines)
        session = session_factory()
        session.add(cpg)
        session.commit()

        # Add nodes to db
        print_notice(f'Adding nodes and edges from CPG no.{cpg.id} to database...')
        node_lst = CSVNode.getNodesFromCSV('./csvfiles/nodes.csv', cpg.id, vuln_lines)
        CSVNode.addNodes(node_lst)

        # Add edges to db
        edge_lst = CSVEdge.getEdgesFromCSV('./csvfiles/rels.csv', cpg.id)
        edge_lst += CSVEdge.getEdgesFromCSV('./csvfiles/cpg_edges.csv', cpg.id)
        CSVEdge.addEdges(edge_lst)
        session.close()
        return cpg

    @staticmethod
    def getCPGs():
        session = session_factory()
        cpg_lst = session.query(CSVGraph).all()
        session.close()
        return cpg_lst

    @staticmethod
    def getCPGsByType(vtype, stype):
        session = session_factory()
        cpg_lst = session.query(CSVGraph).filter_by(vuln_type=vtype, set_type=f'{vtype.replace("Safe_","")}_{stype}').all()
        session.close()
        return cpg_lst

    @staticmethod
    def getCPGsBySet(vtype, stype):
        session = session_factory()
        cpg_lst = session.query(CSVGraph).filter_by(set_type=f'{vtype.replace("Safe_", "")}_{stype}').all()
        session.close()
        return cpg_lst


class CSVEdge(Base):
    """ CSV Edge class.
        This is the gorm class to handle cpg edge generated in csv file by phpjoern.
        Edge info will be store in table edge.
    """
    __tablename__ = 'edge'

    id = Column(Integer, primary_key=True)
    in_vertex = Column(Integer)
    out_vertex = Column(Integer)
    type = Column(String)
    var = Column(String)
    cpg_id = Column(Integer)

    def __init__(self, in_vertex, out_vertex, type, cpg_id, var=""):
        self.in_vertex = in_vertex
        self.out_vertex = out_vertex
        self.cpg_id = cpg_id
        self.type = type
        self.var = var

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
                    if len(row) > 3:
                        edge = CSVEdge(row[0], row[1], row[2], cpg_id, row[3])
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
        edge_lst = session.query(CSVEdge).filter(CSVEdge.cpg_id == cpg_id).all()
        session.close()
        return edge_lst


class CSVNode(Base):
    __tablename__ = 'node'

    id = Column(Integer, primary_key=True)
    node_id = Column(Integer)
    cpg_id = Column(Integer)
    # labels = Column(JSON)
    labels = Column(String)
    type = Column(String)
    flags = Column(String)
    lineno = Column(String)
    code = Column(String)
    childnum = Column(String)
    funcid = Column(String)
    classname = Column(String)
    name = Column(String)

    is_vuln = Column(Boolean)

    def __init__(self, node_id, cpg_id, labels, type, flags, lineno, code, childnum, funcid, classname, name, is_vuln):
        self.node_id = node_id
        self.cpg_id = cpg_id
        # self.labels = json.dumps(labels)
        self.labels = labels
        self.type = type
        self.flags = flags
        self.lineno = lineno
        self.code = code
        self.childnum = childnum
        self.funcid = funcid
        self.classname = classname
        self.name = name

        self.is_vuln = is_vuln

    @staticmethod
    def getNodesFromCSV(filepath, cpg_id, vuln_lines):
        node_lst = []
        with open(filepath) as csv_file:
            csv_reader = csv.reader(csv_file, delimiter=',',quoting=csv.QUOTE_NONE)
            line_count = 0
            for row in csv_reader:
                if line_count == 0:
                    line_count += 1
                else:
                    labels = CSVNodeLabels(row[1], row[2], row[3], row[4], row[5], row[6],
                                    row[7], row[8], row[9], row[10], row[11], row[12])
                    # labels = row[2]
                    is_vuln = False

                    if labels.lineno and labels.lineno in vuln_lines:
                        is_vuln = True
                    node = CSVNode(row[0], cpg_id, row[1], row[2], row[3], row[4], row[5], row[6],
                                    row[7], row[8], row[11], is_vuln)
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
        node_lst = session.query(CSVNode).filter(CSVNode.cpg_id == cpg_id).all()
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
                      lineno=int(lineno) if lineno != "" else None,
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
