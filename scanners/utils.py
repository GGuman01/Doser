from urllib.parse import urlparse


def get_domain_name(url):
    parsed_url = urlparse(url)
    domain_name = parsed_url.netloc
    return domain_name
