module Main where

import Text.UbuntuCVE.Parser
import Data.UbuntuCVE

import System.Environment
import Control.Monad
import Data.Bifunctor
import qualified Data.ByteString.Lazy.Internal as BS
import Data.Maybe


main :: IO ()
main = do args <- getArgs
          parsed <- mapM (parseFile cveParser) (drop 1 args)
          let cves = catMaybes $ toValidCVE <$> fillParsedCVE emptyParsedCVE <$> parsed
          putStrLn $ cvesToDebsecan (args !! 0) cves
