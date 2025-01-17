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

"""
add palettes pertaining to the sentiment analysis

- positive sentiment: rgb(255, 238, 106)
- negative sentiment: rgb(255, 0, 51)
- neutral sentiment: rgb(255, 255, 255)
- 50% positive sentiment: rgb(236, 220, 119)
- 50% negative sentiment: rgb(216, 120, 120)
- 25% positive sentiment: rgb(136, 255, 38)
- 25% negative sentiment: rgb(252, 124, 124)
"""

def color_mapper(compound_score):
    if compound_score >= 0.75:
        return "rgb(255, 238, 106)"  # positive sentiment
    elif compound_score >= 0.5:
        return "rgb(236, 220, 119)"  # 50% positive sentiment
    elif compound_score >= 0.25:
        return "rgb(136, 255, 38)"   # 25% positive sentiment
    elif compound_score > 0:
        return "rgb(255, 255, 255)"  # neutral sentiment
    elif compound_score > -0.25:
        return "rgb(252, 124, 124)"  # 25% negative sentiment
    elif compound_score > -0.5:
        return "rgb(216, 120, 120)"  # 50% negative sentiment
    else:
        return "rgb(255, 0, 51)" 