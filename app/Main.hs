module Main where

import Lib

import System.Environment
import Control.Monad
import Data.Bifunctor

main :: IO ()
main = do args <- getArgs
          parsed <- mapM (parseFile cveParser) args
          let lengths = countT (0, 0, 0) <$> parsed
          mapM_ (putStrLn . showlength) (zip args lengths)
  where
    showlength (name, l) = name ++ ": " ++ (show l)
    countT cs [] = cs
    countT (d, m, c) ((ReleasePackageStatus _ _ _ _):xs) = countT (d+1, m, c) xs
    countT (d, m, c) ((Metadata _ _):xs) = countT (d, m+1, c) xs
    countT (d, m, c) ((Ignored _):xs) = countT (d, m, c+1) xs
