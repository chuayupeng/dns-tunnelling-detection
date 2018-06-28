import sys
from scapy.all import *
import math
import numpy

class Node(object):
    def __init__(self, data, ancestry):
        self.data = data
        self.children = []
        self.count = 1
        self.ancestry = ancestry

    def add_child(self, obj):
        self.children.append(obj)

    def add_count(self):
        self.count += 1

    def printNodes(self):
        if(len(self.children) != 0):
            if(self.data == ''):
                print("There are " + str(len(self.children)) + " top level domains")
            else:
                print(self.ancestry + " has " + str(len(self.children)) + " subdomains")
            for child in self.children:
                if(self.data == ''):
                    print("    " + child.data + " is a top level domain")
                else:
                    print("     " + child.data + " is a subdomain of " + self.ancestry)
            for child in self.children:		
                child.printNodes()

root = Node('', '')

def method_filter_DNS(pkt):
    global root
    if pkt.haslayer(DNS) and hasattr(pkt.qd, 'qname'):
        #get qname
        qname = pkt.qd.qname
        arrRes = qname.split('.')
        properOrderedTree = list(reversed(arrRes))
        tmp = ''
        node = root
        for domain in properOrderedTree:
            if domain == '':
                node.add_count()
            else:
                exists = False
                for child in node.children:
                    if domain == child.data:
                        exists = True
                        child.add_count()
                        childToGo = child
                        break
                if not exists:
                    if tmp != '':
                        tmp = domain + '.' + tmp
                    else :
                        tmp = domain
                    childToGo = Node(domain, tmp)
                    node.add_child(childToGo)
                node = childToGo


def tree(filename):
    sniff(offline=filename, prn=method_filter_DNS, store=0)
    root.printNodes()
    
def main():
    if len(sys.argv) < 2:
        print("Usage: python identifyDomain.py filename.pcap")
        sys.exit()
    tree(sys.argv[1])

if __name__ == "__main__":
    main()