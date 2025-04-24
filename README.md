# cloud-report-api
This repo is used to generate cloud reports based on best practices followed in the cloud.

## Steps to Run the Application

1. **Get AWS Credentials**:
   - Retrieve the `secret_key`, `access_key`, and `session_token` from the KF SSO console.
   - Update the credentials in `~/.aws/credentials` under any profile name. For example:
     ```
     SS[KF-PROD-O]
     aws_access_key_id = YOUR_ACCESS_KEY
     aws_secret_access_key = YOUR_SECRET_KEY
     aws_session_token = YOUR_SESSION_TOKEN
     ```

2. **Set the AWS Profile**:
   - Before running the FastAPI app, set the AWS profile using the following command:
     ```bash
     export AWS_PROFILE=KF-PROD-SSO
     ```

3. **Run the FastAPI Application**:
   - Start the FastAPI app using the following command:
     ```bash
     uvicorn main:app --reload
     ```

4. **Access the API**:
   - Open your browser and navigate to `http://127.0.0.1:8000` to access the API.
   - Use the Swagger UI at `http://127.0.0.1:8000/docs` for interactive API documentation.
