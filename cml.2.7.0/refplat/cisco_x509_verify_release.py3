#!/usr/bin/env python3
#
# Copyright (c) 2015-2023 by cisco Systems, Inc.
# All rights reserved.
#---------------------------------------------------------------------------

# This script is used to verify three tier certificate
# chain and verify file signature using openssl.

import sys
import os
import argparse
import urllib.request, urllib.parse, urllib.error
import hashlib
import shutil
import subprocess
import tempfile


#constants
PROG_NAME = "cisco_x509_verify_release.py3"

#menu constants
MENU_MAIN_DESC = "Image signing application. This will verify the certificate chain"\
                 " and image signature using openssl commands."
CISCO_X509_VERIFY_REL_VERSION = "PY3.1.8"

#color constants
RED = '\033[31m'
YELLOW = '\033[33m'
OKMAGENTA = '\033[35m'
OKGREEN = '\033[32m'
OKBLUE = '\033[34m'
OKCYAN = '\033[36m'
OKWHITE = '\033[97m'

ENDC = '\033[0m'
BOLD = '\033[1m'
UNDERLINE = '\033[4m'

FAIL    = RED    + ' ' + BOLD       #red
WARNING = YELLOW + ' ' + BOLD       #orange
DEBUGCOLOR = OKMAGENTA + ' ' + BOLD

#globals
rel_root_cert_file = "crcam2.cer"
rel_root_cert_url = "https://www.cisco.com/security/pki/certs/"+rel_root_cert_file
rel_root_cert_sha256 = "cd85167b3935e27bcc3b0f5fa24c8457882d0bb994f88269a7f72829d957eae9"
rel_subca_cert_file = "innerspace.cer"
rel_subca_cert_url = "https://www.cisco.com/security/pki/certs/"+rel_subca_cert_file
rel_subca_cert_sha256 = "f31e6b39dae6996fdf2045a61be8bd3688a86dfd06c46ce71af4af239f411c56"

cont_rel_root_cert_file = "crrca.cer"
cont_rel_root_cert_url = "https://www.cisco.com/security/pki/certs/"+cont_rel_root_cert_file
cont_rel_root_cert_sha256 = "1997ba40d0d6fafb672c67d5200d0c0846b540d1e431634c2a8923508b2974c0"
xrcont_rel_subca_cert_file = "xrcrrsca.cer"
xrcont_rel_subca_cert_url = "https://www.cisco.com/security/pki/certs/"+xrcont_rel_subca_cert_file
xrcont_rel_subca_cert_sha256 = "c86f7c94650ba37ac0f0a31fe132f375447d90a5319f455298b5620142a1da3e"

vir_rel_root_cert_file = "vuefirca.cer"
vir_rel_root_cert_url = "https://www.cisco.com/security/pki/certs/"+vir_rel_root_cert_file
vir_rel_root_cert_sha256 = "67501b730fe840f05cba7a84cfd26e0f11311e5f9b16ce60004fd97d3f55de4c"
vir_rel_subca_cert_file = "vuefiscav2.cer"
vir_rel_subca_cert_url = "https://www.cisco.com/security/pki/certs/"+vir_rel_subca_cert_file
vir_rel_subca_cert_sha256 = "4f5d920ed0f53651f68789534dc190fe964dd174ff251381b207a129b82d84c0"

local_dir = None
tempCertDir = None
failExpiredCerts = False

"""
LOG() function prints string in requested color on terminal
"""
def LOG(color, string):
    if(sys.platform.find("linux") == -1):
        if(color == FAIL):
            print("Error Log: " + string)
        else:
            print(string)
    else:
        if(color == FAIL):
            print((color + "Error log: " + string + ENDC))
        else:
            print((color + string + ENDC))


"""
execute_command(cmd) function executes the shell command and returns
status and output.
"""
def execute_command(cmd):
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=False, universal_newlines=True)
    out,_ = p.communicate()
    status = p.returncode
    return status, out


"""
cleanup() function deletes any newly created temp files.
"""
def cleanup(args):
    if os.path.exists("ee_pubkey.pem"):
        os.remove("ee_pubkey.pem")

    # only delete certs if they were not locally-sourced (i.e. they were downloaded)
    if(args.cert_dir == None):
        if(root_cert != None and os.path.exists(root_cert)):
            os.remove(root_cert)
        if(subca_cert != None and os.path.exists(subca_cert)):
            os.remove(subca_cert)


"""
url_exists() function checks if provided url link is valid or not
"""
def url_exists(url):
    if(urllib.request.urlopen(url).code >= 400):
        return False
    else:
        return True


"""
verify_cert_sha256() function computes the sha256sum of certificate
and compares with the expected value.
"""
def verify_cert_sha256(cert_name, expected_sha256):
    cert_sha256 = hashlib.sha256(open(cert_name, 'rb').read()).hexdigest()
    if(cert_sha256 == expected_sha256):
        return True
    else:
        LOG(FAIL, "Computed sha256sum of "+cert_name+" = "+cert_sha256)
        LOG(FAIL, "Expected sha256sum of "+cert_name+" = "+expected_sha256)
        return False


"""
convert_cert_to_pem() function converts DER formatted cert
to PEM format.
"""
def convert_cert_to_pem(cert_name):
    with open(cert_name, 'r', 1, 'us-ascii', 'ignore') as f:
        first_line = f.readline()
        if(first_line.find("-----BEGIN CERTIFICATE-----") == -1):
            cmd = ['openssl', 'x509', '-inform', 'der', '-in', cert_name, '-out',  cert_name]
            status, out = execute_command(cmd)
            if(out.find("error") != -1):
                LOG(FAIL, "Failed to convert "+cert_name+"from DER to PEM.")
                LOG(FAIL, out)
                return False

    return True


"""
check_cert() function
 returns True  if a cert is not checked or will not expire in the next second.
 returns False if a cert is checked and WILL     expire in the next second.
 Also logs a warning msg if cert expiration will happen in the next 180 days (6 months).
"""
def check_cert(cert_name, printed_name, failExpired):
    cmd = ['openssl', 'x509', '-enddate', '-in', cert_name, '-noout']
    status, out = execute_command(cmd)
    end_date = out[9::]
    if (failExpired):
        LOG(OKBLUE,printed_name+" expiration date is "+end_date)

    cmd = ['openssl', 'x509', '-checkend', '1', '-in', cert_name, '-noout']
    status, out = execute_command(cmd)
    if(status != 0):
        LOG(FAIL, printed_name+" expired on "+end_date)
        if (failExpired):
            return False
    else:
        SIX_MONTHS = 15552000
        cmd = ['openssl', 'x509', '-checkend', str(SIX_MONTHS), '-in', cert_name, '-noout']
        status, out = execute_command(cmd)
        if(status != 0):
            LOG(WARNING, "WARNING: "+printed_name+" expires on "+end_date)

    return True



"""
download_cert() function downloads a certificate from provided
url link if its a valid url.
"""
def download_cert(cert_url):
    cert_name = "N/A"
    if(url_exists(cert_url)):
        cert_name = cert_url.split('/')[-1]
        urllib.request.urlretrieve(cert_url, cert_name)
    else:
        LOG(FAIL, "Download certificate failed.")
    return cert_name


"""
verify_3tier_cert_chain() function verifies the 3 tier cert chain.
returns 0 if successful
"""
def verify_3tier_cert_chain(rootca, subca, ee_cert, rootHash, subcaHash):
    status = 0
    if(rootHash != None and verify_cert_sha256(rootca, rootHash) == False):
        return -1
    if(subcaHash != None and verify_cert_sha256(subca, subcaHash) == False):
        return -1

    # create a temp dir and copy certs there
    tempCertDir = tempfile.mkdtemp();
    tempca = tempCertDir+"/tempRootCA.pem"
    tempsubca = tempCertDir+"/tempSubCA.pem"
    tempee = tempCertDir+"/tempEE.pem"
    shutil.copyfile(rootca, tempca)
    shutil.copyfile(subca, tempsubca)
    shutil.copyfile(ee_cert, tempee)

    # convert any DER certs to PEM format, and verify they aren't expired
    if (convert_cert_to_pem(tempca) == False):
        status = -1
    elif (convert_cert_to_pem(tempsubca) == False):
        status = -1
    elif (convert_cert_to_pem(tempee) == False):
        status = -1
    elif (check_cert(tempca, rootca, failExpiredCerts) == False):
        status = -1
    elif (check_cert(tempsubca, subca, failExpiredCerts) == False):
        status = -1
    elif (check_cert(tempee, ee_cert, failExpiredCerts) == False):
        status = -1

    if (status == -1):
        shutil.rmtree(tempCertDir)
        return status

    #verify root and subca certificate
    cmd = ['openssl', 'verify', '-CAfile', tempca, tempsubca]
    status, out = execute_command(cmd)

    if(out.find("error") != -1 or status != 0):
        LOG(FAIL, "Verification of root and subca certificate failed.")
        LOG(FAIL, out)
        shutil.rmtree(tempCertDir)
        return -1

    #verify end-entity certificate
    cmd = ['openssl', 'verify', '-CAfile', tempca, '-untrusted', tempsubca, tempee]
    status, out = execute_command(cmd)

    if(out.find("error") != -1 or status != 0):
        LOG(FAIL, "Failed to verify root, subca and end-entity certificate chain.")
        LOG(FAIL, out)
        return -1
    else:
        LOG(OKGREEN, "Successfully verified root, subca and end-entity certificate chain.")
        return status


"""
fetch_pubkey_from_cert() function retrieves public key from x509
PEM certificate.
"""
def fetch_pubkey_from_cert(cert_name):
    cmd = ['openssl', 'x509', '-pubkey', '-noout', '-in', cert_name]
    f = open("ee_pubkey.pem", "w")
    p = subprocess.Popen(cmd, stdout=f, stderr=subprocess.PIPE, shell=False, universal_newlines=True)
    _,err = p.communicate()
    status = p.returncode
    f.close()

    if(status != 0):
        LOG(FAIL, "Failed to fetch a public key from x509 PEM certificate")
        LOG(FAIL, err)
    else:
        LOG(OKGREEN, "Successfully fetched a public key from "+cert_name+".")
    
    return status


"""
verify_dgst_signature() function verifies the signature of an image.
"""
def verify_dgst_signature(args):
    if(args.sha256):
        sha_version = "-sha256"
    else:
        sha_version = "-sha512"

    cmd = ['openssl', 'dgst', sha_version, '-verify', 'ee_pubkey.pem', '-signature', args.signature, args.image_name]
    status, out = execute_command(cmd)

    if(status != 0):
        LOG(FAIL, "Failed to verify dgst signature of "+args.image_name+".")
        LOG(FAIL, out)
    
    return status


"""
verify_smime_signature() function verifies the openssl smime signature of an image.
"""
def verify_smime_signature(args):
    cmd = ['openssl', 'smime', '-verify', '-binary', '-in', args.signature, '-inform', args.sig_type, '-content', args.image_name, '-noverify', '-nointern', '-certfile', args.ee_cert, '-out', '/dev/null']
    status, out = execute_command(cmd)

    if(status != 0):
        LOG(FAIL, "Failed to verify smime signature of "+args.image_name+".")
        LOG(FAIL, out)
    
    return status


"""
verify_signature() function verifies the image signature using either smime or dgst
openssl command.
"""
def verify_signature(args):
    if(args.verify_type == "smime"):
        status = verify_smime_signature(args)
    else:
        status = fetch_pubkey_from_cert(args.ee_cert)
        if(status != 0):
            return 1
        status = verify_dgst_signature(args)
    return status


"""
command_handler() is a handler function 
"""
def command_handler(args):
    global root_cert
    global subca_cert
    global l_rel_root_cert_file
    global l_rel_subca_cert_file
    local_dir = None
    tempCertDir = None
    root_cert = None
    subca_cert = None

    #validate and download root certificate
    l_rel_root_cert_file = ""
    l_rel_root_cert_url = ""
    l_rel_root_cert_sha256 = ""
    l_rel_subca_cert_file = ""
    l_rel_subca_cert_url = ""
    l_rel_subca_cert_sha256 = ""
    if (args.virtual):
        l_rel_root_cert_file = vir_rel_root_cert_file
        l_rel_root_cert_url = vir_rel_root_cert_url
        l_rel_root_cert_sha256 = vir_rel_root_cert_sha256
        l_rel_subca_cert_file = vir_rel_subca_cert_file
        l_rel_subca_cert_url = vir_rel_subca_cert_url
        l_rel_subca_cert_sha256 = vir_rel_subca_cert_sha256
    elif (args.container):
        l_rel_root_cert_file = cont_rel_root_cert_file
        l_rel_root_cert_url = cont_rel_root_cert_url
        l_rel_root_cert_sha256 = cont_rel_root_cert_sha256
        if (args.container == 'xr'):
            l_rel_subca_cert_file = xrcont_rel_subca_cert_file
            l_rel_subca_cert_url = xrcont_rel_subca_cert_url
            l_rel_subca_cert_sha256 = xrcont_rel_subca_cert_sha256
    else :
        l_rel_root_cert_file = rel_root_cert_file
        l_rel_root_cert_url = rel_root_cert_url
        l_rel_root_cert_sha256 = rel_root_cert_sha256
        l_rel_subca_cert_file = rel_subca_cert_file
        l_rel_subca_cert_url = rel_subca_cert_url
        l_rel_subca_cert_sha256 = rel_subca_cert_sha256

    #setup local dir if specified
    if(args.cert_dir != None):
        local_dir = args.cert_dir

    # Download rootCA certificate or use local cache
    if(local_dir != None):
        root_cert = local_dir+"/"+l_rel_root_cert_file
        LOG(OKGREEN, "Using locally-provided CA certificate "+root_cert)
    else:
        LOG(OKGREEN, "Retrieving CA certificate from "+l_rel_root_cert_url+" ...")
        root_cert = download_cert(l_rel_root_cert_url)
        if(root_cert == "N/A"):
            LOG(FAIL, "Failed to retrieve "+l_rel_root_cert_url+".")
            cleanup(args)
            return 1

    # Download SubCA certificate or use local cache
    if(local_dir != None):
        subca_cert = local_dir+"/"+l_rel_subca_cert_file
        LOG(OKGREEN, "Using locally-provided SubCA certificate "+subca_cert)
    else:
        LOG(OKGREEN, "Retrieving SubCA certificate from "+l_rel_subca_cert_url+" ...")
        subca_cert = download_cert(l_rel_subca_cert_url)
        if(subca_cert == "N/A"):
            LOG(FAIL, "Failed to retrieve "+l_rel_subca_cert_url+".")
            cleanup(args)
            return 1

    #verify 3 tier certificate chain
    rHash = l_rel_root_cert_sha256
    sHash = l_rel_subca_cert_sha256
    status = verify_3tier_cert_chain(root_cert, subca_cert, args.ee_cert, rHash, sHash)

    if(status != 0):
        cleanup(args)
        return status

    #verify signature
    status = verify_signature(args)
    if(status == 0):
        LOG(OKGREEN, "Successfully verified the signature of "+args.image_name+" using "+args.ee_cert)

    cleanup(args)
    return status


"""
verify_parser_options() is used to verify input arguments.
It returns error if any required argument is missing.
"""
def verify_parser_options(args):
    if(args.image_name != None):
        if(not os.path.exists(args.image_name)):
            LOG(FAIL, "'"+args.image_name+"' does not exist")
            return 1
    if(args.signature != None):
        if(not os.path.exists(args.signature)):
            LOG(FAIL, "'"+args.signature+"' does not exist")
            return 1
    if(args.ee_cert != None):
        if(not os.path.exists(args.ee_cert)):
            LOG(FAIL, "'"+args.ee_cert+"' does not exist")
            return 1
    if(args.cert_dir != None):
        if(not os.path.exists(args.cert_dir)):
            LOG(FAIL, "'"+args.cert_dir+"' does not exist")
            return 1

    if(args.failExpiredCerts == True):
        global failExpiredCerts
        failExpiredCerts = True

    return 0


"""
arg_parser() is used to setup command line options.
"""
def arg_parser():
    #setup main parser
    pmain = argparse.ArgumentParser(prog=PROG_NAME, description=MENU_MAIN_DESC)
    
    #version argument
    pmain.add_argument("-V", "--version", action='version', version=CISCO_X509_VERIFY_REL_VERSION)

    #certificate argument
    pmain.add_argument("-e", "--ee_cert", metavar = "<ee_cert_name>", dest = "ee_cert", required = True, help = "Local path to End-entity certificate in PEM format")

    #signature file argument
    pmain.add_argument("-s", "--signature", metavar = "<signature_file>", dest = "signature", required = True, help = "Filename containing image signature")

    #input image argument
    pmain.add_argument("-i", "--image_name", metavar = "<image_name>", dest = "image_name", required = True, help = "Image name")
    
    #cert_dir argument
    pmain.add_argument("-c", "--cert_dir", metavar = "<cert_dir>", dest = "cert_dir", required = False, help = "directory to find local certs")

    #virtual cert chain
    pmain.add_argument("-root_type", "--virtual", dest = "virtual", required = False, help = "Using virtual cert chain ")

    #container cert chain
    pmain.add_argument("--container", choices = ['xr'], dest = "container", required = False, help = "Using container cert chain (ignored if virtual set)")

    #openssl verify type argument
    pmain.add_argument("-v", "--verify_type", choices = ['dgst', 'smime'], default = 'dgst', dest = "verify_type", required = False, help = "Verify type: dgst|smime")

    #openssl verify type argument for SMIME only
    pmain.add_argument("--sig_type", choices = ['DER', 'PEM'], default = 'PEM', dest = "sig_type", required = False, help = "signature encoding (optional, used only for smime, dflt is PEM)")

    #hashing algorithm argument
    group_input = pmain.add_mutually_exclusive_group(required=False)
    group_input.add_argument("-sha256", action = "store_true", dest = "sha256", help = "Using sha256 hashing algorithm (required only for 'dgst')")
    group_input.add_argument("-sha512", action = "store_true", dest = "sha512", help = "Using sha512 hashing algorithm (required only for 'dgst')")
    
    #option to skip cert expiration check
    pmain.add_argument("--failExpiredCerts", action = "store_true", dest = "failExpiredCerts", help = "Check certs for expiration")

    pmain.set_defaults(func=command_handler)

    return pmain


"""
main function for STO image signing script
to verify cert chain and bulk hash signatures.
"""
def main():
    #setup console menu parsers
    pmain = arg_parser()

    #parse args
    args = pmain.parse_args()

    #manually verify the input arguments
    if(verify_parser_options(args) != 0):
        return 1

    #invoke appropriate handler function
    status = args.func(args)

    return status


"""
Starting point
"""
if __name__ == "__main__":
    sys.exit(main())

