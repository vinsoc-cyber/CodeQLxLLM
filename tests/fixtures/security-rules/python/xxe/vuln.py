from lxml import etree

def parse(data):
    parser = etree.XMLParser(resolve_entities=True)
    return etree.fromstring(data, parser)
