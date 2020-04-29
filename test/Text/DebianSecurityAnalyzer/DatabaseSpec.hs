module Text.DebianSecurityAnalyzer.DatabaseSpec where

import Text.DebianSecurityAnalyzer.Database
import Data.DebianSecurityAnalyzer.CVE
import qualified Data.UbuntuSecurityTracker.CVE as U
import qualified Data.UbuntuSecurityTracker.CVE.Package as UP

import Test.Hspec
import Test.QuickCheck

main :: IO ()
main = hspec spec

spec :: Spec
spec = do
  describe "VULNERABILITIES SECTION" $ do
    describe "renderVulnerability: CVE to debsecan's vulnerability format" $ do
      it "should respect debsecan's format (empty fields)" $ do
        renderVulnerability CVE { name=""
                                , description=""
                                , priority=Nothing
                                , isRemote=Nothing
                                , affected=[] }
        `shouldBe`
        ",,"
      it "should respect debsecan's format (populated fields)" $ property $
        \n d  -> renderVulnerability CVE { name=n
                                         , description=d
                                         , priority=Nothing
                                         , isRemote=Nothing
                                         , affected=[] } `shouldBe` n ++ ",," ++ d