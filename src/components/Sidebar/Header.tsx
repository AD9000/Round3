import React from "react"
import { Link } from "gatsby"
import { scale } from "../../utils/typography"

import { ThemeToggler } from "gatsby-plugin-dark-mode"
import { DarkModeMoon } from "./DarkModeIndicator"
import { LightModeSun } from "./LightModeIndicator"

const toggle = (
  <ThemeToggler>
    {({ toggleTheme, theme }) => {
      const isDarkMode = theme === "dark"
      if (theme == null) {
        return null
      }

      return (
        <button
          aria-label="theme-switch"
          className="leading-none p-1"
          onClick={() => toggleTheme(isDarkMode ? "light" : "dark")}
        >
          {isDarkMode ? <DarkModeMoon /> : <LightModeSun />}
        </button>
      )
    }}
  </ThemeToggler>
)

interface HeaderProps {
  title: string
}

const Header = ({ title }: HeaderProps) => {
  return (
    <>
      {toggle}
      <h2
        style={{
          ...scale(1),
          marginBottom: 0,
          marginTop: 0,
          fontFamily: `Montserrat, sans-serif`,
        }}
      >
        <Link
          style={{
            boxShadow: `none`,
            color: `inherit`,
          }}
          to={`/`}
        >
          {title}
        </Link>
      </h2>
    </>
  )
}

export { Header }
