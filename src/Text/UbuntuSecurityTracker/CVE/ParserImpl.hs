module Text.UbuntuSecurityTracker.CVE.ParserImpl
  ( cveParser
  , parseWithErrors
  , linecomment
  , keyvalue
  , release
  , package
  , status
  , notes
  , releasepackagestatus
  ) where

import Data.Functor
import Data.Bifunctor
import Data.List
import Data.UbuntuCVE
import Data.UbuntuSecurityTracker.CVE.Token
import System.Exit
import Text.Parsec
import Text.Parsec.String

--
-- HELPERS
--
whitespace = char ' '

whitespaces = many whitespace

key = (:) <$> upper <*> many (noneOf "\n:")

value =
  intercalate "\n" <$>
  many1 (noneOf "\n") `sepEndBy` try (many1 newline >> whitespace)

release = (:) <$> lower <*> many (noneOf "\n _") <?> "release identifier"

package = many1 (noneOf ":") <?> "package name"

status :: Parser Status
status =
  try (string "DNE" $> DNE) <|> try (string "ignored" $> IGNORED) <|>
  try (string "not-affected" $> NOTAFFECTED) <|>
  try (string "needs-triage" $> NEEDSTRIAGE) <|>
  try (string "needed" $> NEEDED) <|>
  try (string "active" $> ACTIVE) <|>
  try (string "deferred" $> DEFERRED) <|>
  try (string "pending" $> PENDING) <|>
  try (string "released-esm" $> RELEASEDESM) <|>
  try (string "released" $> RELEASED) <|>
  pure IGNORED <?> "status information"

notes =
  (between (char '(') (char ')') rest <|> between (char '[') (char ']') rest) <?>
  "additional notes or version"
  where
    ibetween open close p = do
      o <- open
      x <- p
      c <- close
      return $ [o] ++ x ++ [c]
    inside =
      many1 (noneOf "[()]\n") <|> ibetween (char '(') (char ')') rest <|>
      ibetween (char '[') (char ']') rest
    rest = concat <$> many inside

-- PARSES A COMMENT LINE
-- #<comment>
-- -<comment>
linecomment =
  (Ignored <$> (oneOf "#-" *> many (noneOf "\n"))) <?> "a commented line"

-- PARSES A KEY/VALUE PAIR
-- <Key>: <value>
-- <Key>:
--  <value>
-- <Key>: <some\n
--  value>
keyvalue = keyvalue' <?> "a key/value pair"
  where
    keyvalue' = do
      k <- key
      char ':'
      whitespaces
      many $ try (string "\n ")
      v <- option "" value
      return $ Metadata k v

-- PARSES A RELEASE/PACKAGE/STATUS LINE
-- <release>_<source-package>: <status> (<version/notes>)
-- <release>_<source-package>: <status> (<version/notes>) (<notes2>)
-- <release>_<source-package>: <status> (<version/notes>) (<notes2>) (<notes3>)
releasepackagestatus =
  releasepackagestatus' <?> "release/package/status information"
  where
    releasepackagestatus' = do
      r <- release
      char '_'
      p <- package
      char ':'
      whitespaces
      s <- status
      whitespaces
      ns <- notes `sepEndBy` whitespaces
      let rps = RPS r p s
      if null ns
        then return $ rps Nothing
        else return $ rps (Just $ intercalate "\n" ns)

-- PARSES THE UBUNTU CVE TRACKER FILE FORMAT
cveParser = (validline `sepEndBy` many newline) <* eof
  where
    validline = try keyvalue <|> try releasepackagestatus <|> try linecomment

parseWithErrors :: String -> Either String [Token]
parseWithErrors s = bimap show id $ parse cveParser "" s
