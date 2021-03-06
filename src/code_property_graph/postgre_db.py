from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

from configparser import ConfigParser

CONFIG_FILE = 'database.ini'
SECTION     = 'postgresql'


def config():
    # create a parser
    parser = ConfigParser()
    # read config file
    parser.read('src/code_property_graph/database.ini')

    # get section, default to postgresql
    dbConfig = {}
    if parser.has_section(SECTION):
        params = parser.items(SECTION)
        for param in params:
            dbConfig[param[0]] = param[1]
    else:
        raise Exception('Section {0} not found in the {1} file'.format(SECTION, CONFIG_FILE))
    return dbConfig

params = config()
engine = create_engine(f'postgresql://{params["user"]}:{params["password"]}@{params["host"]}:{params["port"]}'
                           f'/{params["database"]}')
Base = declarative_base()

def session_factory():


    # params = config()
    # use session_factory() to get a new Session
    _SessionFactory = sessionmaker(bind=engine)

    return _SessionFactory()





