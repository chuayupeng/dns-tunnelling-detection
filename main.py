from scapy.all import *
import sys
import math
import numpy as np  
import pandas as pd  
from sklearn import utils 
from sklearn import svm
from sklearn import metrics
from sklearn.model_selection import train_test_split 

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

trainingPackets = []
testPackets = []

def calculateEntropy(text):
    if not text: 
        return 0 
    entropy = 0
    text = text.translate(None, '._-')
    for x in range(256): 
        p_x = float(text.count(chr(x)))/len(text) 
        if p_x > 0: 
            entropy += - p_x*math.log(p_x, 2) 
    return entropy
def extractDNSQueryEntropy(entropyData, isTraining):
    global trainingPackets
    global testPackets
    if isTraining:
        for packetWithBool in trainingPackets:
            pktEntropyValue = calculateEntropy(packetWithBool[0].qd.qname)
            entropyData.append(pktEntropyValue)
    else:
        for packet in testPackets:
            pktEntropyValue = calculateEntropy(packet.qd.qname)
            entropyData.append(pktEntropyValue)
    return entropyData
def populateTree(root, pkt):
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
def buildTree(root, isTraining):
    global trainingPackets
    global testPackets
    if isTraining:
        for packetWithBool in trainingPackets:
            populateTree(root, packetWithBool[0])
    else:
        for packet in testPackets:
            populateTree(root, packet)
def saveTrainingPackets(normal):
    def sniffPrnFn(pkt):
        global trainingPackets
        if pkt.haslayer(DNS) and hasattr(pkt.qd, 'qname'):
            trainingPackets.append([pkt, normal])
    return sniffPrnFn
def saveTestPackets(pkt):
    global testPackets
    if pkt.haslayer(DNS) and hasattr(pkt.qd, 'qname'):
        testPackets.append(pkt)
def sniffTrainingPackets(filename, normal):
    sniff(offline=filename, prn=saveTrainingPackets(normal), store=0)
def sniffTestPackets(filename):
    sniff(offline=filename, prn=saveTestPackets, store=0)
def calculateSubdomainCount(subdomainCountData, root, isTraining):
    global trainingPackets
    global testPackets
    if isTraining:
        for packetWithBool in trainingPackets:
            arrToCalculate = list(reversed(packetWithBool[0].qd.qname.split('.')))[1:]
            count = 0
            tmpPtr = root
            for item in arrToCalculate:
                for child in tmpPtr.children:
                    if child.data == item:
                        tmpPtr = child
                        count += len(child.children)
                        break
            subdomainCountData.append(count)
    else:
        for packet in testPackets:
            arrToCalculate = list(reversed(packet.qd.qname.split('.')))[1:]
            count = 0
            tmpPtr = root
            for item in arrToCalculate:
                for child in tmpPtr.children:
                    if child.data == item:
                        tmpPtr = child
                        count += len(child.children)
                        break
            subdomainCountData.append(count)            
    return subdomainCountData
def calculateQnamesLen(qnamesLen, isTraining):
    global trainingPackets
    global testPackets
    if isTraining:
        for packetWithBool in trainingPackets:
            qnamesLen.append(len(packetWithBool[0].qd.qname))
    else:
        for packet in testPackets:
            qnamesLen.append(len(packet.qd.qname))
    return qnamesLen
def modifyData(entropyData, subdomainCountData, qnamesLen, isTraining):
    global trainingPackets
    global testPackets
    dataForDataFrame = []
    i = 0
    if isTraining:
        while i < len(trainingPackets):
            dataForDataFrame.append([trainingPackets[i][0], trainingPackets[i][1], entropyData[i], subdomainCountData[i], qnamesLen[i]])
            i+=1
    else:
        while i < len(testPackets):
            dataForDataFrame.append([entropyData[i], subdomainCountData[i], qnamesLen[i]])
            i+=1            
    return dataForDataFrame
def trainModel(dataForDataFrame):
    data = pd.DataFrame.from_records(dataForDataFrame, columns=['packet', 'attack', 'entropy', 'subdomainCount', 'queryNameLength'])
    target=data['attack']
    outliers=target[target == -1]
    nu = float(outliers.shape[0])/target.shape[0]
    print("outliers.shape", outliers.shape)  
    print("outlier fraction", nu)
    data.drop(['packet', 'attack'], axis=1, inplace=True)
    train_data, test_data, train_target, test_target = train_test_split(data, target, train_size = 0.85) 
    model = svm.OneClassSVM(nu=nu, kernel='rbf', gamma=0.00005)  
    model.fit(data)
    preds = model.predict(test_data)  
    targs = test_target
    print("accuracy: ", metrics.accuracy_score(targs, preds))  
    print("precision: ", metrics.precision_score(targs, preds))  
    print("recall: ", metrics.recall_score(targs, preds))  
    print("f1: ", metrics.f1_score(targs, preds))  
    print("area under curve (auc): ", metrics.roc_auc_score(targs, preds))
    return model    
def testModel(model, filename):
    root = Node('','')
    entropyData = []
    subdomainCountData = []
    qnamesLen = []
    sniffTestPackets(filename)
    entropyData = extractDNSQueryEntropy(entropyData, False)
    buildTree(root, False)
    subdomainCountData = calculateSubdomainCount(subdomainCountData, root, False)
    qnamesLen = calculateQnamesLen(qnamesLen, False)
    testData = modifyData(entropyData, subdomainCountData, qnamesLen, False)    
    preds = model.predict(testData)
    pktdump = scapy.utils.PcapWriter("results.pcap", append=True, sync=True)
    print("Analysis Completed.")
    print("Saving suspicious packets below to pcap file...(results.pcap)")
    #print("Suspicious Query Names flagged out:")
    #print("------------------------------")
    i = 0
    while i < len(preds):
        if preds[i] == -1:
            #print(testPackets[i].qd.qname)
	    pktdump.write(testPackets[i])
        i+=1
def testFeatureExtraction(goodFileName, badFileName):
    root = Node('', '')
    entropyData = []
    subdomainCountData = []
    qnamesLen = []   
    sniffTrainingPackets(goodFileName, 1)
    sniffTrainingPackets(badFileName, -1)
    entropyData = extractDNSQueryEntropy(entropyData, True)
    buildTree(root, True)
    subdomainCountData = calculateSubdomainCount(subdomainCountData, root, True)
    qnamesLen = calculateQnamesLen(qnamesLen, True)
    return modifyData(entropyData, subdomainCountData, qnamesLen, True)
def main():
    if len(sys.argv) < 3:
        print("Usage: python main.py good.pcap bad.pcap fileToExamine.pcap")
        sys.exit()
    trainingData = testFeatureExtraction(sys.argv[1], sys.argv[2])
    model = trainModel(trainingData)
    testModel(model, sys.argv[3])
if __name__ == "__main__":
    main()
