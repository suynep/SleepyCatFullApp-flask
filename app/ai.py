import nltk
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
