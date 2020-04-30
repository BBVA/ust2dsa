{-|
Copyright 2020 Banco Bilbao Vizcaya Argentaria, S.A.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-}
module Text.UbuntuSecurityTracker.CVE.ParserImplSpec where

import Data.UbuntuSecurityTracker.CVE.Token
import Text.UbuntuSecurityTracker.CVE.ParserImpl

import Test.Hspec
import Test.Hspec.Parsec
import Text.Parsec

main :: IO ()
main = hspec spec

spec :: Spec
spec = do
  describe "PARSING METADATA" $ do
    describe "the key-value parser" $ do
      let keyvalue' = parse keyvalue ""
      it "should parse keys with no values" $
        do keyvalue' "Key:" `shouldParse` Metadata "Key" ""
      it "should parse keys with no values (containing just spaces)" $
        do keyvalue' "Key:   " `shouldParse` Metadata "Key" ""
      it "should parse single-line key values" $
        do keyvalue' "Key: value" `shouldParse` Metadata "Key" "value"
      it "should parse multi-line key value" $
        do keyvalue' "Key:\n line1\n line2"
           `shouldParse` Metadata "Key" "line1\nline2"
      it "should parse multi-line key value starting in the first line" $
        do keyvalue' "Key: line1\n line2"
           `shouldParse` Metadata "Key" "line1\nline2"
      it "should stop parsing when another line starts" $
        do keyvalue' "Key1: line1\n line2\nKey2: something"
           `shouldParse` Metadata "Key1" "line1\nline2"
  describe "PARSING RELEASE/PACKAGE/STATUS INFORMATION" $ do
    describe "the release parser" $ do
      let release' = parse release ""
      it "should parse release names" $ do
        release' "releasename" `shouldParse` "releasename"
      it "should stop at '_'" $ do
        release' "releasename_something" `shouldParse` "releasename"
      it "should fail on uppercase names" $ do
        release' `shouldFailOn` "Releasename_something"
    describe "the package parser" $ do
      let package' = parse package ""
      it "should parse package names" $ do
        package' "packagename" `shouldParse` "packagename"
      it "should stop at ':'" $ do
        package' "packagename: something" `shouldParse` "packagename"
    describe "the status parser" $ do
      let status' = parse status ""
      it "should parse DNE" $ do status' "DNE" `shouldParse` DNE
      it "should parse ignored" $ do status' "ignored" `shouldParse` IGNORED
      it "should parse not-affected" $ do
        status' "not-affected" `shouldParse` NOTAFFECTED
      it "should parse needs-triage" $ do
        status' "needs-triage" `shouldParse` NEEDSTRIAGE
      it "should parse needed" $ do status' "needed" `shouldParse` NEEDED
      it "should parse active" $ do status' "active" `shouldParse` ACTIVE
      it "should parse deferred" $ do status' "deferred" `shouldParse` DEFERRED
      it "should parse pending" $ do status' "pending" `shouldParse` PENDING
      it "should parse released" $ do status' "released" `shouldParse` RELEASED
      it "should parse released-esm" $ do
        status' "released-esm" `shouldParse` RELEASEDESM
      it "should parse empty string as IGNORED" $ do
        status' "" `shouldParse` IGNORED
    describe "the notes parser" $ do
      let notes' = parse notes ""
      it "should parse notes between parenthesis" $ do
        notes' "(foo bar)" `shouldParse` "foo bar"
      it "should parse notes between brackets" $ do
        notes' "[foo bar]" `shouldParse` "foo bar"
      it "should parse notes containings () and []" $ do
        notes' "(foo [bar] (baz))" `shouldParse` "foo [bar] (baz)"
      it "should fail on notes containing newlines" $ do
        notes' `shouldFailOn` "(foo \n baz)"
    describe "the releasepackagestatus parser" $ do
      let releasepackagestatus' = parse releasepackagestatus ""
      it "should parse releasepackagestatus info without comments" $
        do releasepackagestatus' "release_package: DNE"
           `shouldParse` RPS "release" "package" DNE Nothing
      it "should parse releasepackagestatus info with comments" $
        do releasepackagestatus' "release_package: DNE (comment)"
           `shouldParse` RPS "release" "package" DNE (Just "comment")
      it "should parse releasepackagestatus info with multiple comments" $
        do releasepackagestatus' "release_package: DNE (comment1) (comment2)"
           `shouldParse` RPS "release" "package" DNE (Just "comment1\ncomment2")
  describe "PARSING COMMENTS" $ do
    describe "the linecomment parser" $ do
      let linecomment' = parse linecomment ""
      it "should parse lines starting with '#' as comments" $
        do linecomment' "#this is a comment"
           `shouldParse` Ignored "this is a comment"
  describe "PARSING *UBUNTU CVE TRACKER* FILE FORMAT" $ do
    let cveParser' = parse cveParser ""
    it "should parse empty CVE files" $ do cveParser' "" `shouldParse` []
    it "should parse well-formed (non-empty) CVE files" $
      do cveParser'
           "Candidate: CVE-2020-11111\n\n\nPatches_jackson-databind:\nupstream_jackson-databind: released (2.9.10.4)\n"
         `shouldParse` [ (Metadata "Candidate" "CVE-2020-11111")
                       , (Metadata "Patches_jackson-databind" "")
                       , (RPS
                            "upstream"
                            "jackson-databind"
                            RELEASED
                            (Just "2.9.10.4"))
      ]
    it "should fail on malformed entry" $
      do cveParser' `shouldFailOn` "invalidKey: \n"
