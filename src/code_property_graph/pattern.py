from sqlalchemy import Column, Boolean, Integer, String, and_

from src.code_property_graph.postgre_db import Base, session_factory


class Pattern(Base):
    """ CSV graph class.
        This is the gorm class to handle cpg graph generated in csv file by phpjoern.
        Graph info will be store in table cpg.
    """
    __tablename__ = 'pattern'

    id = Column(Integer, primary_key=True)
    pattern = Column(String)
    matched_gid = Column(String)
    min_support = Column(Integer)
    max_support = Column(Integer)
    vuln_type = Column(String)
    mine_type = Column(Integer)

    def __init__(self, pattern, matched_gid, min_sup, max_sup, vuln_type, mine_type):
        self.pattern = pattern
        self.matched_gid = matched_gid
        self.min_support = min_sup
        self.max_support = max_sup
        self.vuln_type = vuln_type
        self.mine_type = mine_type

    @staticmethod
    def addEdges(pattern_lst):
        session = session_factory()
        session.bulk_save_objects(pattern_lst)
        session.commit()
        session.close()