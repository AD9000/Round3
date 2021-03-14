import React from "react"
import { Grid, Theme } from "@material-ui/core"
import { makeStyles, ThemeProvider } from "@material-ui/styles"

import Sidebar from "./Sidebar/Sidebar"
import MainContent from "./MainContent/MainContent"
import AppTheme from "./Theme"
import "./global.css"

const useStyles = makeStyles((theme: Theme) => {
  return {
    respDir: {
      display: "flex",
      [theme.breakpoints.down("sm")]: {
        flexDirection: "column",
      },
      [theme.breakpoints.up("md")]: {
        height: "100vh",
      },
    },
    respBar: {
      display: "flex",
      [theme.breakpoints.down("sm")]: {
        height: "35vh",
      },
    },
    respMain: {
      [theme.breakpoints.up("md")]: {
        height: "100vh",
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
        // overflow: "auto",
      }}
      className={classes.respDir}
    >
      <Grid
        item
        container
        xs={12}
        md={4}
        lg={3}
        className={classes.respBar}
        style={{ flex: "0 0 auto" }}
      >
        <Sidebar title={title} />
      </Grid>
      <Grid
        item
        container
        xs={12}
        md={8}
        lg={9}
        style={{
          flex: "1 1 auto",
          overflow: "auto",
        }}
        className={classes.respMain}
      >
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
