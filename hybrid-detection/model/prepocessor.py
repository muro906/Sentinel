"""
Handle the preprocessing of the data before feeding it to the model.
Preprocessing includes: RobustScaler wrapper and stochastic Augmenter
"""

from math import fabs
import numpy as np
import joblib
from sklearn.preprocessing import RobustScaler
from config.constants import FEATURE_DIM

class TrafficScaler:
    """
    This is a thin wrapper on the RobustScaler from sklearn.
    It is used to scale the traffic data.
    """
    def __init__(self):
        self._scaler = RobustScaler()
    
    def fit(self, X: np.ndarray) -> 'TrafficScaler':
        """
        Fit the scaler on training data X of shape(N, FEATURE_DIM).
        Used only on training split
        """
        self._scaler.fit(X)
        return self

    def transform(self, X: np.ndarray) -> np.ndarray:
        """
        Scale X and return a feature a float32 np.ndarray of same shape
        """
        return self._scaler.transform(X).as_type(np.float32)
    
    
    def fit_transform(self, X) -> np.ndarray:
        return self.fit(X).transform(X)
    
    def save(self, path:str):
        """Persist the fitted scaler to disk"""
        joblib.dump(self._scaler, path)
    
    @classmethod
    def load(cls, path:str) -> 'TrafficScaler':
        """
        Load a previously fitted scaler from disk
        """
        instance = cls()
        instance._scaler = joblib.load(path)
        return instance


class Augmenter:
    """
    This is a stochastic data augmentation class that creates positive pairs for self-supervised contrastive learning.

    Given a sample x_i in the dataset, the augmenter returns the pair (x_i, x_i_aug) where x_i_aug is the augmented version of x_i
    """

    def __init__(
        self,
        noise: float = 0.05,
        dropout_max: int = 3,
        jitter_range: tuple = (0.9, 1.1)
        ):
        self.noise = noise
        self.dropout_max = dropout_max
        self.jitter_range = jitter_range
    
    def augment(self, x: np.ndarray) -> np.ndarray:
        """
        The function applies 1-2 randomly chosen augmentations to a single feature vector

        The Augmentations include;
            - gaussian_noise : add N(0, noise) to all continuous features
            - feature_dropout: zero out to dropout_max random_features
            - scale_jitter: multiply all continuous features by U(jitter_range)

        Returns augmented copy of x (original x is not modified)
        """
        x_aug = x.copy()
        n_augs = np.random.randint(1, 3) 
        choices = np.random.choice(["noise", "dropout", "jitter"], size=n_augs, replace=False)
        
        for aug in choices:
            if aug == "noise":
                x_aug = self._gaussian_noise(x_aug)
            elif aug == "dropout":
                x_aug = self._feature_dropout(x_aug)
            elif aug == "jitter":
                x_aug = self._scale_jitter(x_aug)
        return x_aug.as_type(np.float32)
    
    def augment_batch(self, X: np.ndarray) -> np.ndarray:
        """
        Apply augmentation to a batch of samples
        Returns:
            np.ndarray: (N, FEATURE_DIM)
        """
        return np.stack([self.augment(x) for x in X], axis=0)
    
    def _gaussian_noise(self,x: np.ndarray) -> np.ndarray:
        """
        Add gaussian noise to the input
        """
        return x + np.random.normal(0,self.noise, size=x.shape).as_type(np.float32)
    
    def feature_dropout(self, x: np.ndarray) -> np.ndarray:
        """ Zero out random features"""
        n = np.random.randint(1, self.dropout_max + 1)
        idx = np.random.choice(len(x), size=n, replace=False)
        x = x.copy()
        x[idx] = 0.0
        return x
    
    def scale_jitter(self, x: np.ndarray) -> np.ndarray:
        lo, hi = self.jitter_range
        scale = np.random.uniform(lo, hi, size = x.shape).astype(np.float32)
        return x * scale


        