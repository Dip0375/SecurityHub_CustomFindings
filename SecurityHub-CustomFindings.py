import json
import boto3

sns = boto3.client('sns')

def lambda_handler(event, context):
    
    # Extract details from JSON event
    detailType = event["detail-type"]
    region = event["region"]
    accountId = event["account"]
    
    # Initialize the subject and message variables
    subject = "AWS Security Notification"
    message = ""
    
    # Security Hub Insight Results
    if detailType == "Security Hub Insight Results":
        action = event["detail"]["actionDescription"]
        message = f"Alert: {detailType} in {region} for account: {accountId}\nAction description: {action}"
    
    elif "Security Hub Findings" in detailType:
        finding = event["detail"]["findings"][0]
        
        # Extract additional information
        findingId = finding["Id"]
        findingName = finding["Title"]
        severity = finding["Severity"]["Label"]
        resourceType = finding["Resources"][0]["Type"]
        resourceArn = finding["Resources"][0]["Id"]
        remediationText = finding["Remediation"]["Recommendation"]["Text"]
        remediationUrl = finding["Remediation"]["Recommendation"].get("Url", "No URL provided")
        
        # Update subject to the finding name
        subject = findingName
        
        # Format message
        message = (f"Alert: {detailType} in {region} for account: {accountId}\n"
                   f"Finding ID: {findingId}\n"
                   f"Finding Name: {findingName}\n"
                   f"Severity: {severity}\n"
                   f"Resources Type: {resourceType}\n"
                   f"Resources ARN: {resourceArn}\n"
                   f"Remediation: {remediationText}\n"
                   f"Remediation URL: {remediationUrl}")
    
    # AWS API Call via CloudTrail finding
    elif detailType == "AWS API Call via CloudTrail":
        time = event["detail"]["eventTime"]
        eventName = event["detail"]["eventName"]
        requestParameters = json.dumps(event["detail"]["requestParameters"], indent=2)
        
        # Set the subject as the event name
        subject = eventName
        
        message = (f"Alert: {detailType} in {region} for account: {accountId} at time: {time}\n"
                   f"Event: {eventName}\n"
                   f"Request parameters: {requestParameters}")
        
    # If the event doesn't match any of the above, format a default message
    else:
        message = str(event)
    
    # Publish the SNS message with a subject
    response = sns.publish(
        TopicArn="arn:aws:sns:ap-south-1:730335441980:security-alerts",
        Message=message,
        Subject=subject
    )
    
    return {
        'statusCode': 200,
        'body': json.dumps('Success!')
}
