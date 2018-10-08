import math
import sys
import numpy as np  
import pandas as pd  
from scapy.all import *
from sklearn import utils, svm
import treeNode
import trainModel

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

def buildTree(root, isTraining):
    global trainingPackets
    global testPackets
    if isTraining:
        for packetWithBool in trainingPackets:
            treeNode.populateTree(root, packetWithBool[0])
    else:
        for packet in testPackets:
            treeNode.populateTree(root, packet)

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

def testModel(model, filename):
    root = treeNode.Node('','')
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
    i = 0
    while i < len(preds):
        if preds[i] == -1:
            pktdump.write(testPackets[i])
        i+=1

def testFeatureExtraction(goodFileName, badFileName):
    root = treeNode.Node('', '')
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

def trainBlind(filename):
    root = treeNode.Node('', '') 
    entropyData = []
    subdomainCountData = []
    qnamesLen = []
    sniffTestPackets(filename)
    entropyData = extractDNSQueryEntropy(entropyData, False)
    buildTree(root, False)
    subdomainCountData = calculateSubdomainCount(subdomainCountData, root, False)
    qnamesLen = calculateQnamesLen(qnamesLen, False)
    testData = modifyData(entropyData, subdomainCountData, qnamesLen, False)
    model = svm.OneClassSVM(nu=0.01, kernel='rbf', gamma=0.00005)  
    model.fit(testData)    
    testModel(model, filename)

def main():
    if len(sys.argv) != 2 and len(sys.argv) < 3:
        print("Usage: python main.py fileToExamine.pcap                      to do unsupervised outlier detection")
        print("Usage: python main.py good.pcap bad.pcap fileToExamine.pcap   for additional checks on accuracy of model")
        sys.exit()
    if(len(sys.argv) == 2):
        trainBlind(sys.argv[1])
    else:
        trainingData = testFeatureExtraction(sys.argv[1], sys.argv[2])
        model = trainModel.trainModel(trainingData)
        testModel(model, sys.argv[3])
if __name__ == "__main__":
    main()
