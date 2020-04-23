module Text.UbuntuSecurityTracker.CVE.PackageImplSpec where

import qualified Data.UbuntuSecurityTracker.CVE.Token as T (Status(..))
import Data.UbuntuSecurityTracker.CVE.Token hiding (Status(..))
import qualified Data.UbuntuSecurityTracker.CVE.Package as P (Status(..))
import Data.UbuntuSecurityTracker.CVE.Package hiding (Status(..), Package (..))

import Test.Hspec

main :: IO ()
main = hspec spec

spec :: Spec
spec = do
  describe "SIMPLIFY UBUNTU SECURITY TRACKER PACKAGE STATUS" $ do
    it "should map Ubuntu's package status to VULNERABLE" $ do
      mapStatus T.NEEDED (Just "1.0") `shouldBe` (P.VULNERABLE "1.0")
      mapStatus T.ACTIVE (Just "1.0") `shouldBe` (P.VULNERABLE "1.0")
      mapStatus T.PENDING (Just "1.0") `shouldBe` (P.VULNERABLE "1.0")
      mapStatus T.DEFERRED (Just "1.0") `shouldBe` (P.VULNERABLE "1.0")
    it "should map Ubuntu's package status to NOTVULNERABLE" $ do
      mapStatus T.DNE (Just "1.0") `shouldBe` (P.NOTVULNERABLE "1.0")
      mapStatus T.NEEDSTRIAGE (Just "1.0") `shouldBe` (P.NOTVULNERABLE "1.0")
      mapStatus T.NOTAFFECTED (Just "1.0") `shouldBe` (P.NOTVULNERABLE "1.0")
      mapStatus T.IGNORED (Just "1.0") `shouldBe` (P.NOTVULNERABLE "1.0")
      mapStatus T.RELEASED (Just "1.0") `shouldBe` (P.NOTVULNERABLE "1.0")
      mapStatus T.RELEASEDESM (Just "1.0") `shouldBe` (P.NOTVULNERABLE "1.0")
