import React from "react"

// import Footer from "./footer" // footer isn't used yet
import { makeStyles } from "@material-ui/styles"

const useStyles = () =>
  makeStyles({
    mainFlex: { display: "flex", flex: 1 },
    mainWrapper: {
      padding: "1% 5%",
      backgroundColor: "var(--bg)",
    },
  })()

const MainContent = ({ children }) => {
  const classes = useStyles()
  return (
    <div className={`${classes.mainFlex} ${classes.mainWrapper}`}>
      <main className={classes.mainFlex}>{children}</main>
      {/* <Footer /> */}
    </div>
  )
}

export default MainContent
