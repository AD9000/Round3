import React from "react"
import { Grid, Theme } from "@material-ui/core"
import { makeStyles, ThemeProvider } from "@material-ui/styles"

import Sidebar from "./Sidebar/Sidebar"
import MainContent from "./MainContent/MainContent"
import AppTheme from "./Theme"
import "./global.css"

const useStyles = makeStyles((theme: Theme) => {
  console.log("theme: ", theme)
  return {
    respDir: {
      display: "flex",
      [theme.breakpoints.down("sm")]: {
        flexDirection: "column",
      },
    },
    respBar: {
      display: "flex",
      [theme.breakpoints.down("sm")]: {
        minHeight: "35vh",
      },
    },
  }
})

const LayoutThemed = ({ title, children }) => {
  const classes = useStyles()
  return (
    <Grid
      container
      style={{
        backgroundColor: "var(--bg)",
        color: "var(--textNormal)",
        transition: "color 0.2s ease-out, background 0.2s ease-out",
        minHeight: "100vh",
      }}
      className={classes.respDir}
    >
      <Grid item md={5} lg={4} xl={3} className={classes.respBar}>
        <Sidebar title={title} />
      </Grid>
      <Grid item md={7} lg={8} xl={9}>
        <MainContent>{children}</MainContent>
      </Grid>
    </Grid>
  )
}

const Layout = props => {
  return (
    <ThemeProvider theme={AppTheme}>
      <LayoutThemed {...props} />
    </ThemeProvider>
  )
}

export default Layout
