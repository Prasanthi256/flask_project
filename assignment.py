import re
from flask import Flask,request
app = Flask(__name__)


@app.route("/v1/sanitized/input",methods = ["post"])
def  input_validation():
	#check if input is Json or not
	try:
		res =request.json
	except Exception as err:
		print(err)
		return "not a valid json"

	#check if result has  payload as key.
	if 'payload' in res:
		data  = res['payload']
		value=check_sql_injection(data)
	else:
		return "payload  key is missing"
	
	if value:
		return {"result" : "unsanitized"}
	else:
		return {"result" : "sanitized"}



def check_sql_injection(data):
	#regex  for checking  comments select, insert,drop,delete
	#checking for execution of stored proc

	match = (
		re.search(r'(\%27)|(\')|(\-\-)|(\%23)|(#)', data, re.IGNORECASE) or
		re.search(r'((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))', data, re.IGNORECASE) or
		re.search(r'\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))', data, re.IGNORECASE) or
		re.search(r'((\%27)|(\'))union|select|insert|drop|delete|waitfor delay|SLEEP', data, re.IGNORECASE) or
		re.search(r'/exec(\s|\+)+(s|x)p\w+/ix',data,re.IGNORECASE)
	)
	return match


if __name__ == '__main__':
	app.run(debug = True)