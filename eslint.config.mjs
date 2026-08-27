import js from "@eslint/js";
import globals from "globals";
import { defineConfig } from "eslint/config";
import jestPlugin from "eslint-plugin-jest";

export default defineConfig([
  { files: ["**/*.{js,mjs,cjs}"], plugins: { js }, extends: ["js/recommended"], languageOptions: { globals: globals.node } },
  { files: ["**/*.js"], languageOptions: { sourceType: "script" } },
  {
    files: ["**/*.test.js"],
    plugins: { jest: jestPlugin },
    languageOptions: { globals: globals.jest },
    rules: {
      ...jestPlugin.configs.recommended.rules
    }
  }
]);
