import nltk
import os

# Define the path for nltk_data
nltk_data_path = os.path.expanduser("~/nltk_data")

# Check if the nltk_data directory exists
if not os.path.exists(nltk_data_path):
    print(f"Directory {nltk_data_path} does not exist. Creating and downloading data...")
    nltk.download('vader_lexicon', download_dir=nltk_data_path)
else:
    # Check if vader_lexicon is specifically downloaded
    try:
        nltk.data.find('sentiment/vader_lexicon.zip')
        print("VADER lexicon already downloaded.")
    except LookupError:
        print("Downloading VADER lexicon...")
        nltk.download('vader_lexicon', download_dir=nltk_data_path)


from nltk.sentiment.vader import SentimentIntensityAnalyzer


def sentiment_analyser(user_data):
    return SentimentIntensityAnalyzer().polarity_scores(user_data)["compound"]


def color_mapper(compound_score):
    if compound_score >= 0.05:
        return "rgb(255, 238, 106)"
    elif compound_score <= -0.05:
        return "rgb(255, 0, 51)"
    else:
        return "rgb(255, 255, 255)"
