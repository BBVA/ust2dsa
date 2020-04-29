module Text.DebianSecurityAnalyzer.DatabaseSpec where

import Text.DebianSecurityAnalyzer.Database
import Data.DebianSecurityAnalyzer.CVE
import qualified Data.UbuntuSecurityTracker.CVE as U
import qualified Data.UbuntuSecurityTracker.CVE.Package as UP

import Test.Hspec

main :: IO ()
main = hspec spec

spec :: Spec
spec = do
  describe "VULNERABILITIES SECTION" $ do
    describe "renderVulnerability: CVE to debsecan's vulnerability format" $ do
      it "should respect debsecan's format" $ do
        renderVulnerability CVE { name="foo"
                                , description="bar"
                                , priority=Nothing
                                , isRemote=Nothing
                                , affected=[] }
        `shouldBe`
        "foo,,bar"
