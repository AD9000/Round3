import React from "react"
import { makeStyles } from "@material-ui/core"
import { About } from "./About/About"
import { Header } from "./Header"

const useStyles = () =>
  makeStyles({
    sideFlex: {
      display: "flex",
      flexBasis: "auto",
      flexGrow: 1,
      flexShrink: 1,
    },
    sidebar: {
      justifyContent: "center",
      padding: "1% 2%",
      backgroundColor: "var(--lightBg)",
      flex: "1 1 auto",
      // height: "100vh",
      color: "#e0e0e0",
    },
  })()

interface SidebarProps {
  title: string
}
const Sidebar = ({ title }: SidebarProps) => {
  const classes = useStyles()
  return (
    <div className={`${classes.sidebar} ${classes.sideFlex}`}>
      <div className="flex flex-col justify-center items-center">
        <Header title={title} />
        <About />
      </div>
    </div>
  )
}

export default Sidebar
