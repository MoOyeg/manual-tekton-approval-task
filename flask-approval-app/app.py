from time import sleep
from flask import render_template, request, Flask
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, TextAreaField
import os
import logging
import sys
import requests

app = Flask(__name__)
app_failure_status=False
app_failure_message=""
app_approved=False
app_dispproved=False

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)


class PostForm(FlaskForm):
    '''Set Form to be used fields'''
    authorized_user = StringField('authorized_user')
    pipelinerun = StringField('pipelinerun')
    tekton_instance_name = StringField('tekton_instance_name')
    approval_cmd= StringField('approval_cmd')
    approve = SubmitField('submit')
    disapprove = SubmitField('disapprove')

def set_app_failure_status(msg):
    '''Set App Failure Status'''
    global app_failure_status
    global app_failure_message
    
    app_failure_message=msg
    app_failure_status=True

def get_app_failure_status():
    '''Get App Failure Status'''
    global app_failure_status
    return app_failure_status    

def get_app_failure_message():
    '''Get App Failure Message'''
    global app_failure_message
    return app_failure_message

def onfailure_update_disk(msg):
    '''Update Disk with Failure'''
    try:        
        with open(os.environ.get('APPROVAL_FILE_LOCATION'), 'w') as f:
            f.write("Error")
    except Exception as e:
        logger.error("Error writing error decision to disk - will exit")
    set_app_failure_status(msg)
    return get_app_failure_message()


def set_approval_status(approval_string):
    '''Set Approval Status'''
    global app_approved
    global app_dispproved
    
    try:
        with open(os.environ.get('APPROVAL_FILE_LOCATION'), 'w') as f:
            f.write(approval_string)
    except Exception as e:
        error_msg="Error writing approval decision to disk - will exit"
        logger.error("{}-{}".format(error_msg,e))
        return onfailure_update_disk(error_msg)

    
    if approval_string == os.environ.get('UNIQUE_APPROVED_SECRET'):
        logger.info("Promotion Process has been Approved, will continue Pipeline Run")
        app_approved=True
        return "Promotion Process has been Approved, will continue Pipeline Run"
    elif approval_string == os.environ.get('UNIQUE_DENIED_SECRET'):
        logger.info("Promotion Process has been Denied, will end Pipeline Run")
        app_dispproved=True
        return "Promotion Process has been Denied, will end Pipeline Run"

def get_approval_status():
    '''Get Approval Status,will return True if App approved or if App disapproved'''
    return app_approved or app_dispproved 
    

def get_app_valid_status():
    '''Get App Valid Status , return True if App has not already been approved or disapproved and if App has not failed'''
    return get_approval_status() and not get_app_failure_status()

try:
    logger.info("Get Flask Secret Key")        
    app.config['SECRET_KEY'] = os.environ.get('APP_COOKIE_SECRET')       
except Exception as e:
    error_msg="Error getting App Cookie Secret from environment - will exit"
    logger.error("{}-{}".format(error_msg,e))
    onfailure_update_disk(error_msg)
    sys.exit(1)
    
if os.environ.get('APP_COOKIE_SECRET') == None or os.environ.get('APP_COOKIE_SECRET') == "":
    error_msg="App Cookie Secret is empty - will exit"
    logger.error("{}".format(error_msg))
    onfailure_update_disk(error_msg)
    sys.exit(1)

@app.route("/")
def home():
    if get_app_valid_status():
        if get_approval_status():
            return "App has already processed request, will not process new requests"
        elif get_app_failure_status():
            return "App has failed to process previous request, will not process new requests"
  
    logger.info("Home Page Accessed")
    form = PostForm()
    try:        
        form.pipelinerun=os.environ.get('PIPELINE_RUN_NAME')
        form.approval_cmd=os.environ.get('PROMOTE_COMMAND')
        form.tekton_instance_name=os.environ.get('TEKTON_INSTANCE_SECRET')        
    except Exception as e:
        error_msg="Error getting $PIPELINE_RUN_NAME or $PROMOTE_COMMAND from environment will exit"
        logger.error("{}-{}".format(error_msg,e))
        onfailure_update_disk(error_msg)
        
    try:
        #form.authorized_user="testuser"
        form.authorized_user=request.authorization.username
        print(dict(request.headers))
        r=requests.get("http://kubernetes.default.svc.cluster.local/apis/user.openshift.io/v1/users/",headers=dict(request.headers)
                       ,cookies=dict(request.cookies))
        print(r.status_code)
        print(r.text)
        token=request.headers.get('X-Forwarded-Access-Token')
        if token is not None:
            with open(os.environ.get('TOKEN_FILE_LOCATION'), 'w') as f:
                f.write(token)
    except Exception as e:
        error_msg="Error getting authorized username from Oauth Proxy"
        logger.error("{}-{}".format(error_msg,e))
        onfailure_update_disk(error_msg)    
    
    logger.info("Approval Requested for Pipeline Run Name: %s",form.pipelinerun)
    return render_template('approval.html', postform=form)

@app.route("/ready",methods=['GET'])
def ready():
    '''Check if App is Ready'''
    if get_app_valid_status():
        logger.info("Ready Page Accessed")
        return "Success", 200
    else:
        logger.error("App is not ready")
        return "Failure", 500


@app.route("/approval_status",methods=['POST'])
def approval_status():
    '''Get Approval Status and Update Disk'''

    if get_app_valid_status():
        if get_approval_status():
            return "App has already processed request, will not process new requests"
        elif get_app_failure_status():
            return "App has failed to process previous request, will not process new requests"
    
    if request.method == 'POST':
        approval_string=""
        if request.form['submit_button'] == 'Approve':
            logger.info("Approval Provided for Pipeline Run Name: %s",os.environ.get('PIPELINE_RUN_NAME'))

            try:
                approval_string=os.environ.get('UNIQUE_APPROVED_SECRET')
            except Exception as e:
                error_msg="Error getting unique approval string info from environment - will exit"
                logger.error("{}-{}".format(error_msg,e))
                return onfailure_update_disk(error_msg)          
               
        elif request.form['submit_button'] == 'Disapprove':
            logger.info("Disapproval Provided for Pipeline Run Name: %s",os.environ.get('PIPELINE_RUN_NAME'))
            try:
                approval_string=os.environ.get('UNIQUE_DENIED_SECRET')                
            except Exception as e:
                error_msg="Error getting unique disapproval string info from environment - will exit"
                logger.error("{}-{}".format(error_msg,e))
                return onfailure_update_disk(error_msg) 
        
    if approval_string == "" or approval_string == None:
        error_msg="Approval/Disapproval String was Empty - will exit"
        logger.error("{}".format(error_msg))
        return onfailure_update_disk(error_msg)   
    
    try: 
        return_msg=set_approval_status(approval_string)
        if get_app_failure_status():
            error_msg=get_app_failure_message()
            logger.error("{} - {}".format("We ran into an error",error_msg))
            return onfailure_update_disk(error_msg)
    except Exception as e:
        error_msg="Error setting approval status - will exit"
        logger.error("{}-{}".format(error_msg,e))
        return onfailure_update_disk(error_msg)
    
    return return_msg    
     

if __name__ == '__main__':
    logger.info("Starting Approval App") 
       
    logger.debug("Get Flask Port")
    port=os.environ.get('OAUTH_APPROVER_PORT')
    if port == None or port == "":
        port=8080
    app.run(host='127.0.0.1', port=port,use_reloader=False)
     
        
        