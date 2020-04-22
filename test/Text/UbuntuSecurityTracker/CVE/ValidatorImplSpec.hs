module Text.UbuntuSecurityTracker.CVE.ValidatorImplSpec where

import Text.UbuntuSecurityTracker.CVE.ValidatorImpl
import Data.UbuntuSecurityTracker.CVE.Staged
import Data.UbuntuSecurityTracker.CVE.Token
import Test.Hspec

main :: IO ()
main = hspec spec

spec :: Spec
spec = do

  describe "FILL STAGED STRUCT" $ do
    it "should return an empty Staged on empty Token list" $ do
      fillStaged [] `shouldBe` emptyStaged

    it "should fill the name field with the `Candidate` Metadata" $ do
      fillStaged [ Metadata "Candidate" "foo" ]
      `shouldBe`
      emptyStaged{name=Just "foo"}

    it "should fill the description field with the `Description` Metadata" $ do
      fillStaged [ Metadata "Description" "foo" ]
      `shouldBe`
      emptyStaged{description=Just "foo"}

    it "should ignore any comments" $ do
      fillStaged [ Ignored "This is a comment"
                 , Metadata "Candidate" "bar"]
      `shouldBe`
      emptyStaged{name=Just "bar"}

    it "should ignore any other metadata" $ do
      fillStaged [ Metadata "Foo" "bar"]
      `shouldBe`
      emptyStaged
