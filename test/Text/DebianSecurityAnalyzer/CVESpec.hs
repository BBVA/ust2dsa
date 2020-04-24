module Text.DebianSecurityAnalyzer.CVESpec where

import qualified Data.DebianSecurityAnalyzer.CVE as D
import qualified Data.UbuntuSecurityTracker.CVE as U

import Data.Either
import Test.Hspec

main :: IO ()
main = hspec spec

spec :: Spec
spec = do
  describe "TRANSFORMING UBUNTU'S CVE TO DEBSECAN'S" $ do
    it "should fail when mandatory fields are not present" $ do
      isLeft $ D.mapCVE U.emptyCVE
