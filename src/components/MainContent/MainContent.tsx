import React from "react"

// import Footer from "./footer" // footer isn't used yet
import { makeStyles } from "@material-ui/styles"

const useStyles = () =>
  makeStyles({
    mainFlex: {
      display: "flex",
      flex: 1,
      overflowY: "auto",
    },
    mainWrapper: {
      overflow: "auto",
      padding: "1% 5%",
      marginLeft: "1%",
      backgroundColor: "var(--bg)",
    },
    mainBox: {
      flexDirection: "column",
      "& article": {
        display: "flex",
        flexDirection: "column",
        maxWidth: "100%",
      },
    },
  })()

const MainContent = ({ children }) => {
  const classes = useStyles()
  return (
    <div className={`${classes.mainFlex} ${classes.mainWrapper}`}>
      <main className={`${classes.mainFlex} ${classes.mainBox}`}>
        {children}
      </main>
      {/* <Footer /> */}
    </div>
  )
}

export default MainContent
