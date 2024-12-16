# To Develop Locally:

## GNU/Linux

In your terminal, run the following commands sequentially to install all the development dependencies:

`git clone https://github.com/suynep/SleepyCatFullApp-flask.git SleepyCat`
`cd SleepyCat/`
`python3 -m virtualenv .venv`
`source ./.venv/bin/activate`
`pip3 install -r requirements.txt`

Now, ensure you have a database connection set up at [https://mongodb.com] Cluster. 

### Ensure that environment variables are set in the `.env` file:
**Required variables**: 
- MONGODB_USER_PW=<your-connection-pass-string>

Then run: 

`python3 app.py`

