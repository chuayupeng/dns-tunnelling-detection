import pandas as pd
from sklearn.model_selection import train_test_split 
from sklearn import svm, metrics

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
