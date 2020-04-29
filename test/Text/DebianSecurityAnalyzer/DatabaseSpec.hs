module Text.DebianSecurityAnalyzer.DatabaseSpec where

import Data.DebianSecurityAnalyzer.CVE
import qualified Data.UbuntuSecurityTracker.CVE as U
import qualified Data.UbuntuSecurityTracker.CVE.Package as UP
import Text.DebianSecurityAnalyzer.Database

import Data.List.Split
import Data.Bool
import Test.Hspec
import Test.QuickCheck
import Generic.Random

import GHC.Generics

instance Arbitrary U.Priority where
  arbitrary = genericArbitraryU

instance Arbitrary UP.Status where
  arbitrary = genericArbitraryU

instance Arbitrary UP.Package where
  arbitrary = genericArbitraryU

main :: IO ()
main = hspec spec

spec :: Spec
spec = do
  describe "VULNERABILITIES SECTION" $ do
    describe "renderVulnerability: CVE to debsecan's vulnerability format" $ do
      it "should respect debsecan's format (empty fields)" $
        do renderVulnerability
             CVE
               { name = ""
               , description = ""
               , priority = Nothing
               , isRemote = Nothing
               , affected = []
               }
           `shouldBe` ",,"
      it "should respect debsecan's format (populated fields)" $
        property $ \year id d p r aps ->
          let cve = CVE { name = "CVE-" ++ show (year :: Int) ++ "-" ++ show (id :: Int)
                        , description = filter (/= ',') d
                        , priority = p
                        , isRemote = r
                        , affected = aps
                        }
          in splitOn "," (renderVulnerability cve) `shouldBe` [name cve, "", description cve]
    describe "renderPackage: CVE to debsecan's vulnerability format" $ do
      it "should ignore unaffected packages" $
        let cve = CVE { name = "foo"
                      , description = "bar"
                      , priority = Nothing
                      , isRemote = Nothing
                      , affected = []
                      }
        in renderPackage "qux" "quux" cve `shouldBe` Nothing
      it "should render affected package (vulnerable)" $
        property $ \n d r ->
          let cve = CVE { name = n
                        , description = d 
                        , priority = Nothing
                        , isRemote = Nothing
                        , affected = [ UP.Package { UP.name="package"
                                                  , UP.release=r
                                                  , UP.status=UP.VULNERABLE "1.0"
                                                  } ]
                        }
          in renderPackage "qux" "package" cve
             `shouldBe`
             Just "package,S   ,,"
      it "should render affected package (not vulnerable in devel)" $
        property $ \n d ->
          let cve = CVE { name = n
                        , description = d 
                        , priority = Nothing
                        , isRemote = Nothing
                        , affected = [ UP.Package { UP.name="package"
                                                  , UP.release="devel"
                                                  , UP.status=UP.NOTVULNERABLE "1.0"
                                                  } ]
                        }
          in renderPackage "qux" "package" cve
             `shouldBe`
             Just "package,S   ,1.0,"
      it "should render affected package (not vulnerable in upstream)" $
        property $ \n d ->
          let cve = CVE { name = n
                        , description = d 
                        , priority = Nothing
                        , isRemote = Nothing
                        , affected = [ UP.Package { UP.name="package"
                                                  , UP.release="upstream"
                                                  , UP.status=UP.NOTVULNERABLE "1.0"
                                                  } ]
                        }
          in renderPackage "qux" "package" cve
             `shouldBe`
             Just "package,S   ,1.0,"
      it "should render affected package (not vulnerable in other suite)" $
        property $ \n d ->
          let cve = CVE { name = n
                        , description = d 
                        , priority = Nothing
                        , isRemote = Nothing
                        , affected = [ UP.Package { UP.name="package"
                                                  , UP.release="bionic"
                                                  , UP.status=UP.NOTVULNERABLE "1.0"
                                                  }
                                     , UP.Package { UP.name="package"
                                                  , UP.release="feasty"
                                                  , UP.status=UP.NOTVULNERABLE "2.0"
                                                  } ]
                        }
          in renderPackage "qux" "package" cve
             `shouldBe`
             Just "package,S   ,,1.0 2.0"
      it "should render affected package (not vulnerable several suites and devel)" $
        property $ \n d ->
          let cve = CVE { name = n
                        , description = d 
                        , priority = Nothing
                        , isRemote = Nothing
                        , affected = [ UP.Package { UP.name="package"
                                                  , UP.release="devel"
                                                  , UP.status=UP.NOTVULNERABLE "1.0"
                                                  }
                                     , UP.Package { UP.name="package"
                                                  , UP.release="feasty"
                                                  , UP.status=UP.NOTVULNERABLE "2.0"
                                                  } ]
                        }
          in renderPackage "qux" "package" cve
             `shouldBe`
             Just "package,S   ,1.0,2.0"
      it "should render affected package's priority" $
        property $ \n d p ->
          let cve = CVE { name = n
                        , description = d 
                        , priority = Just p
                        , isRemote = Nothing 
                        , affected = [ UP.Package { UP.name="package"
                                                  , UP.release="devel"
                                                  , UP.status=UP.VULNERABLE "1.0"
                                                  }
                                     ]
                        }
          in renderPackage "qux" "package" cve
             `shouldBe`
             Just ("package,S" ++ (show p) ++ "  ,,")
      it "should render affected package's remote flag" $
        property $ \r ->
          let cve = CVE { name = "foo"
                        , description = "bar"
                        , priority = Nothing
                        , isRemote = r
                        , affected = [ UP.Package { UP.name="package"
                                                  , UP.release="devel"
                                                  , UP.status=UP.VULNERABLE "1.0"
                                                  }
                                     ]
                        }
          in renderPackage "qux" "package" cve
             `shouldBe`
             Just ("package,S " ++ (maybe "?" (bool " " "R") r) ++ " ,,")
