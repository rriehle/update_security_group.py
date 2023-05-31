import logging

format = '[%(asctime)s] %(levelname)s in %(module)s: %(message)s'
# DO NOT USE logging.DEBUG in prod unless you want to potentially log passwords
# logging.basicConfig(format=format, level=logging.DEBUG)
logging.basicConfig(format=format, level=logging.INFO)
