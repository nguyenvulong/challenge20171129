from sklearn.metrics import precision_recall_curve
from sklearn.metrics import confusion_matrix

#MalwareFamilyClassifiers
from sklearn.svm import SVC
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.gaussian_process import GaussianProcessClassifier #multi_class: one_vs_one/rest

from RiskInDroid import RiskInDroid
from pymongo import MongoClient
import numpy as np
import hashlib
import sys
import csv

import timeit

THRESHOLD = 50
CSVFILENAME1 = "test1.csv"
CSVFILENAME2 = "test2.csv"

def most_common(lst):
    """return most common element in list"""
    return max(set(lst), key=lst.count)

def score_malware(riskScore):
    if riskScore > THRESHOLD:
        return 1
    else:
        return 0

def preparing_data(file_path):
    """take an APK file as input
       insert its binary Permissions 
       to MongoDB"""
    rid = RiskInDroid()
    file_path = sys.argv[1]
    permissions = rid.get_permission_json(file_path)
    bPermissions =  rid.get_feature_vector_from_json(permissions)
    malicious =  {'malicious':2}

    sha256value = hashlib.sha256(open(file_path, "rb").read()).hexdigest()
    sha256 = {'sha256':sha256value}
    #return rid.calculate_risk(bPermissions)

    record = {**bPermissions,**malicious, **sha256} #merge 2 dictionaries in Python 3.5.x
    print(str(record))
    client = MongoClient('localhost', 27017)
    db = client['Challenge']
    db.bPermissions_test.insert_one(record)
    client.close()

def measure_accuracy():
    rid = RiskInDroid()

    client = MongoClient('localhost', 27017)
    db = client['Challenge']
    cursor = db.bPermissions.find({})
    predictedResult = []
    result = []
    for document in cursor:
        result.append(document["malicious"])
        riskScore = rid.calculate_risk(document)
        predictedResult.append(score_malware(riskScore))
    tn, fp, fn, tp = confusion_matrix(result, predictedResult).ravel()
    print("Accuracy = ",(tp + tn)/( tp + fp + fn + tn))

    client.close()


#measure_accuracy()
def classify_family():
    names = ["RBF SVM", "GBC", "GPC1", "GPCr"]
    classifiers = [
            SVC(), GradientBoostingClassifier(),
            GaussianProcessClassifier(multi_class="one_vs_one"),
            GaussianProcessClassifier(multi_class="one_vs_rest")
            ]

    client = MongoClient('localhost', 27017)
    db = client['Challenge']

    #training model
    sampleMalware = []
    familyMalware = []

    cursor = db.bPermissions_family.find({"malicious":1})
    for document in cursor:
        sampleMalware.append(document["allTypes"])
        familyMalware.append(document["family"])

    #measuring accuracy
    score = []
    classifierModels = []
    for name, clf in zip(names, classifiers):
        clf.fit(sampleMalware,familyMalware)
        classifierModels.append(clf)
        #score.append(np.sum(np.asarray(familyMalware) == np.asarray(predictedResult))/len(sampleMalware)*100)
        #print(np.count_nonzero(np.asarray(resultedFamily) == np.asarray(predictedFamily)))

    csvfile = open(CSVFILENAME1, 'w', newline='')
    csvWriter = csv.writer(csvfile, dialect='excel', quotechar='|', quoting=csv.QUOTE_MINIMAL)
    for sM, fM in zip(sampleMalware, familyMalware):
        classifyResult = []
        for cm in classifierModels:
            classifyResult.append(cm.predict([sM])[0])
        family = most_common(classifyResult)
        print(sM,family,"\n")
        csvWriter.writerow( [family] + [fM])
    csvfile.close()
    #testing Apps & write results to csv file
    rid = RiskInDroid()
    csvfile = open(CSVFILENAME2, 'w', newline='')
    csvWriter = csv.writer(csvfile, dialect='excel', quotechar='|', quoting=csv.QUOTE_MINIMAL)
    cursor = db.bPermissions_family.find({"malicious":2})

    for document in cursor:
        break
        malicious = score_malware(rid.calculate_risk(document))
        sha256value = document["sha256"]
        if malicious == 1:
            classifyResult = []
            for cm in classifierModels:
                classifyResult.append(cm.predict([document["allTypes"]])[0])  #4 predicted results
            family = most_common(classifyResult)
        else:
            family = "na"
        csvWriter.writerow([sha256value] + [str(malicious)] + [family] + [document["family"]])
    csvfile.close()

    client.close()

classify_family()
