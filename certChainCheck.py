
from OpenSSL import SSL,crypto
import socket
import certifi
import pem
import urllib
import re

# Cert Paths
TRUSTED_CERTS_PEM = certifi.where() 
store = crypto.X509Store() # trusted store

def get_cert_chain(target_domain):
    '''
    This function gets the certificate chain from the provided
    target domain. This will be a list of x509 certificate objects.
    '''
    # Set up a TLS Connection
    dst = (target_domain.encode('utf-8'), 443)
    ctx = SSL.Context(SSL.SSLv23_METHOD)
    s = socket.create_connection(dst)
    s = SSL.Connection(ctx, s)
    s.set_connect_state()
    s.set_tlsext_host_name(dst[0])

    # Send HTTP Req (initiates TLS Connection)
    s.sendall('HEAD / HTTP/1.0\n\n'.encode('utf-8'))
    s.recv(16)
    
    # Get Cert Meta Data from TLS connection
    test_site_certs = s.get_peer_cert_chain()
    s.close()
    return test_site_certs

######################################### Helper Functions

""" parse root ca file
    add certs one by one to trusted store"""
def setStore():
    certs = pem.parse_file(TRUSTED_CERTS_PEM)

    for cert in certs:
        root = crypto.load_certificate(crypto.FILETYPE_PEM,str(cert))
        store.add_cert(root)

############################################
"""Check domain against CN and SAN list"""
def checkCN_SAN(cert, domain):

    # get CN
    cn = str(cert.get_subject()).split("CN=")[-1][:-2]
    cn = cn.split(".")[-2]

    # check domain with cn
    x = re.search("(^(www\.)?)+([\.]?" + cn + "+)\.[a-z]{2,5}(:[0-9]{1,5})?(\/.*)?$", domain)

    if (x):
        return True
    else:
        # get SAN list from extensions in cert and look for domain in SAN list
        for i in range(cert.get_extension_count()):
            ext = cert.get_extension(i)           
            if 'subjectAltName' in str(ext.get_short_name()) and domain[4:] in str(ext.get_data()): 
                 return True

    return False

###########################################

""" check cert on chain"""
def checkCert(cert): 

    try:
        store_ctx = crypto.X509StoreContext(store, cert)
        store_ctx.verify_certificate()
        # if verfied add to store
        store.add_cert(cert)
        return True

    except:
        return False
    
##############################################

def x509_cert_chain_check(target_domain: str) -> bool:
    '''
    This function returns true if the target_domain provides a valid 
    x509cert and false in case it doesn't or if there's an error.
    '''
    # trust store set up
    setStore()

    # this returns intermediates and leaf
    chain = get_cert_chain(target_domain)

    # traverse chain from intermediate to leaf
    for i in reversed(range(len(chain))):
        
        # check certs in chain
        if checkCert(chain[i]) and not chain[i].has_expired():
            # if leaf
            if i == 0 and checkCN_SAN(chain[i], target_domain): 
                return True
    
    return False

if __name__ == "__main__":
    
    # Standalone running to help you test your program
    print("Certificate Validator...")
    target_domain = input("Enter TLS site to validate: ")
    print("Certificate for {} verifed: {}".format(target_domain, x509_cert_chain_check(target_domain)))
