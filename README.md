
## RESOLVE IT - AI Integrated Application for Urban Governance

Resolve IT is an AI-Integrated Web application designed to help citizens report and resolve locality-based issues such as potholes, streetlight failures, and sanitation problems. The platform enables users to submit complaints, which are then processed using an NLP model (DistilBERT) to categorize and route them efficiently. Additionally, it integrates a YOLO-based road damage detection system that allows users to upload images of damaged roads, which are analyzed for automated issue classification.


## Tech Stack

**Client:** HTML, CSS, Bootstrap, JavaScript

**Server:** Flask, PyMongo

**Database:** MongoDB

**Machine Learning:** DistilBERT (Text - NLP) and YOLO V8 (Image Classification)




## Features

### User Features

 - Register and log in securely

 - Submit queries(e.g., pothole, streetlight issues)

 - Upload images of road damage for automated detection

 - Track the status of submitted complaints

 - Receive email notifications on issue updates

### Admin Features
 - View and manage submitted user queries

 - Analyze complaints with AI-powered categorization (DistilBERT NLP model)

 - Review road damage analysis results from uploaded images (YOLO model)

 - Update issue statuses and assign resolution teams

### AI & Image Processing Features
 - NLP model (DistilBERT) for categorizing text-based queries

 - YOLO-based model for detecting and classifying road damage from images

 - Store and manage results in a centralized database


## Run Locally

Clone the Project

```bash
git clone https://github.com/GouthamKumar025/resolve-it.git
```

Go to the Project

```bash
cd project
```

Install dependencies

```bash
pip install
```

Start the server

```bash
python app.py
```

## Authors

- [Goutham Kumar S](https://github.com/GouthamKumar025)
- [Balaji K](https://github.com/Balajibala82489)
- [Dhanushram S](https://github.com/dhanushram27)


