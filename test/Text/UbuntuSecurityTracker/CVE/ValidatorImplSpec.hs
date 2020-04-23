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
      fillStaged []
      `shouldBe`
      Right emptyStaged

    it "should fill the name field with the `Candidate` Metadata" $ do
      honorToken emptyStaged ( Metadata "Candidate" "foo" )
      `shouldBe`
      Right emptyStaged{name=Just "foo"}

    it "should fill the description field with the `Description` Metadata" $ do
      honorToken emptyStaged ( Metadata "Description" "foo" )
      `shouldBe`
      Right emptyStaged{description=Just "foo"}

    it "should fill the priority field with the `Priority` Metadata (low)" $ do
      honorToken emptyStaged ( Metadata "Priority" "low" )
      `shouldBe`
      Right emptyStaged{priority=Just L}

    it "should fill the priority field with the `Priority` Metadata (medium)" $ do
      honorToken emptyStaged ( Metadata "Priority" "medium" )
      `shouldBe`
      Right emptyStaged{priority=Just M}

    it "should fill the priority field with the `Priority` Metadata (high)" $ do
      honorToken emptyStaged ( Metadata "Priority" "high" )
      `shouldBe`
      Right emptyStaged{priority=Just H}

    it "should report when the priority field contains something unknown" $ do
      honorToken emptyStaged ( Metadata "Priority" "very-low-maybe-dontknow" )
      `shouldBe`
      Left "unknown priority value"

    it "should ignore any comments" $ do
      fillStaged [ Ignored "This is a comment"
                 , Metadata "Candidate" "bar"]
      `shouldBe`
      Right emptyStaged{name=Just "bar"}

    it "should ignore any other metadata" $ do
      honorToken emptyStaged ( Metadata "Foo" "bar" )
      `shouldBe`
      Right emptyStaged
