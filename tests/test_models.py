from ml.models.supervised import SupervisedDetector

def test_supervised_model_trains_and_predicts():
 rows=[]; labels=[]
 for i in range(12):
  rows.append({'bytes':float(i+1),'packets':1.0,'dst_port':443.0}); labels.append('normal' if i<6 else 'volumetric_ddos')
 m=SupervisedDetector().fit(rows,labels); label,score=m.predict({'bytes':50,'packets':10,'dst_port':443})
 assert label in {'normal','volumetric_ddos'} and 0<=score<=1
