from src.code_property_graph.cpg import *
from src.code_property_graph.postgre_db import session_factory, config
from sqlalchemy import create_engine


def query_CPGs():
    session = session_factory()
    CPGs_query = session.query(CSVGraph)
    session.close()
    return CPGs_query.all()


if __name__ == "__main__":
    # cpg = CPG.generate_CPG("/home/mn404/Documents/Thesis/Project/tools/phpjoern/test.php")
    params = config()
    engine = create_engine(
        f'postgresql://{params["user"]}:{params["password"]}@{params["host"]}:5432/{params["database"]}')
    CSVGraph.__table__.drop(engine)
    CSVNode.__table__.drop(engine)
    CSVEdge.__table__.drop(engine)